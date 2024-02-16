//--------------------------------------------------------------------------
// Copyright (C) 2017-2024 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// control_mgmt.cc author Bhagya Tholpady <bbantwal@cisco.com>
//                 author Devendra Dahiphale <ddahipha@cisco.com>
//                 author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "control_mgmt.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/un.h>

#include <cassert>
#include <unordered_map>

#include "log/messages.h"
#include "main/shell.h"
#include "main/snort_config.h"
#include "utils/stats.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "control.h"

using namespace snort;

static constexpr unsigned MAX_CONTROL_FDS = 16;
static constexpr unsigned MAX_CONTROL_IDLE_TIME = 60;

static int listener = -1;
static socklen_t sock_addr_size = 0;
static struct sockaddr* sock_addr = nullptr;
static struct sockaddr_in in_addr;
static struct sockaddr_un unix_addr;
static std::unordered_map<int, ControlConn*> controls;

#define READY 1
#define DEAD  2

struct FdEvents
{
    int fd;
    unsigned flag;
};

#ifdef __linux__

//-------------------------------------------------------------------------
// Linux epoll descriptor polling implementation (Linux-only)
//-------------------------------------------------------------------------

#include <sys/epoll.h>

static int epoll_fd = -1;
static unsigned nfds;

static void delete_expired_controls();

static bool init_controls()
{
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1)
    {
        ErrorMessage("Failed to create epoll file descriptor: %s\n", get_error(errno));
        return false;
    }
    nfds = 0;
    return true;
}

static bool register_control_fd(const int fd)
{
    if (nfds + 2 >= MAX_CONTROL_FDS)
        delete_expired_controls();

    if (nfds == MAX_CONTROL_FDS)
    {
        WarningMessage("Failed to add file descriptor, exceed max (%d)\n", nfds);
        return false;
    }

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event))
    {
        WarningMessage("Failed to add file descriptor %d to epoll(%d): %s\n", fd, epoll_fd, get_error(errno));
        return false;
    }

    nfds++;
    return true;
}

static void unregister_control_fd(const int, const int curr_fd)
{
    // File descriptors are automatically removed from the epoll instance when they're closed
    if (curr_fd != -1 && epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr_fd, nullptr))
        WarningMessage("Failed to remove file descriptor %d from epoll(%d): %s (%d)\n", curr_fd, epoll_fd, get_error(errno), errno);
    nfds--;
}

static bool poll_control_fds(FdEvents ready[MAX_CONTROL_FDS], unsigned& nready)
{
    if (epoll_fd == -1 || nfds == 0)
        return false;

    static struct epoll_event events[MAX_CONTROL_FDS];
    int ret = epoll_wait(epoll_fd, events, nfds, 0);
    if (ret <= 0)
    {
        if (ret < 0 && errno != EINTR)
            ErrorMessage("Failed to poll control descriptors: %s\n", get_error(errno));
        return false;
    }
    nready = ret;
    for (int i = 0; i < ret; i++)
    {
        struct epoll_event* ev = &events[i];
        ready[i].fd = ev->data.fd;
        ready[i].flag = 0;
        if (ev->events & POLLIN)
            ready[i].flag |= READY;
        if (ev->events & (POLLHUP | POLLERR))
        {
            if (ev->events & POLLERR)
                ErrorMessage("Failed to poll control descriptor %d!\n", ev->data.fd);
            ready[i].flag |= DEAD;
        }
    }

    return true;
}

static void term_controls()
{
    if (epoll_fd >= 0)
    {
        close(epoll_fd);
        epoll_fd = -1;
    }
}

#else

//-------------------------------------------------------------------------
// POSIX poll descriptor polling implementation (default)
//-------------------------------------------------------------------------

static struct pollfd pfds[MAX_CONTROL_FDS];
static nfds_t npfds;

static bool init_controls()
{
    npfds = 0;
    return true;
}

static bool register_control_fd(const int fd)
{
    if (npfds == MAX_CONTROL_FDS)
        return false;

    struct pollfd* pfd = &pfds[npfds];
    pfd->fd = fd;
    pfd->events = POLLIN;
    npfds++;

    return true;
}

static void unregister_control_fd(const int orig_fd, const int)
{
    for (nfds_t i = 0; i < npfds; i++)
    {
        if (pfds[i].fd == orig_fd)
        {
            npfds--;
            // If this wasn't the last element, swap that in
            if (i < npfds)
                pfds[i].fd = pfds[npfds].fd;
            break;
        }
    }
}

static bool poll_control_fds(FdEvents ready[MAX_CONTROL_FDS], unsigned& nready)
{
    if (npfds == 0)
        return false;

    int ret = poll(pfds, npfds, 0);
    if (ret <= 0)
    {
        if (ret < 0 && errno != EINTR)
            ErrorMessage("Failed to poll control descriptors: %s\n", get_error(errno));
        return false;
    }
    nready = 0;
    for (int i = 0; i < npfds; i++)
    {
        struct pollfd* pfd = &pfds[i];
        int fd = pfd->fd;
        ready[nready].fd = fd;
        ready[nready].flag = 0;
        if (pfd->revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            if (pfd->revents & (POLLERR | POLLNVAL))
                ErrorMessage("Failed to poll control descriptor %d!\n", fd);
            ready[nready].flag |= DEAD;
        }
        if (pfd->revents & POLLIN)
            ready[nready].flag |= READY;

        if (ready[nready].flag)
            ++nready;
    }
    return true;
}

static void term_controls()
{
    npfds = 0;
}

#endif

//-------------------------------------------------------------------------
// Platform agnostic private functions
//-------------------------------------------------------------------------

// FIXIT-M make these non-blocking
// FIXIT-M bind to configured ip including INADDR_ANY
// (default is loopback if enabled)
static int setup_socket_family(const SnortConfig* sc)
{
    int family = AF_UNSPEC;

    if (sc->remote_control_port)
    {
        memset(&in_addr, 0, sizeof(in_addr));

        in_addr.sin_family = AF_INET;
        in_addr.sin_addr.s_addr = htonl(0x7F000001);
        in_addr.sin_port = htons(sc->remote_control_port);
        sock_addr = (struct sockaddr*)&in_addr;
        sock_addr_size = sizeof(in_addr);
        family = AF_INET;
    }
    else if (!sc->remote_control_socket.empty())
    {
        std::string fullpath;
        const char* path_sep = strrchr(sc->remote_control_socket.c_str(), '/');
        if (path_sep != nullptr)
            fullpath = sc->remote_control_socket;
        else
            get_instance_file(fullpath, sc->remote_control_socket.c_str());

        memset(&unix_addr, 0, sizeof(unix_addr));
        unix_addr.sun_family = AF_UNIX;
        SnortStrncpy(unix_addr.sun_path, fullpath.c_str(), sizeof(unix_addr.sun_path));
        sock_addr = (struct sockaddr*)&unix_addr;
        sock_addr_size = sizeof(unix_addr);
        unlink(fullpath.c_str());
        family = AF_UNIX;
    }
    return family;
}

static bool accept_conn()
{
    int fd = accept(listener, sock_addr, &sock_addr_size);
    if (fd < 0)
    {
        ErrorMessage("Failed to accept control socket connection: %s\n", get_error(errno));
        return false;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
    {
        ErrorMessage("Failed to put control socket connection in non-blocking mode: %s\n",
                get_error(errno));
        close(fd);
        return false;
    }
    if (!ControlMgmt::add_control(fd, false))
    {
        ErrorMessage("Failed to add control connection for descriptor %d\n", fd);
        close(fd);
        return false;
    }

    // FIXIT-L authenticate, use ssl ?
    return true;
}

static void delete_control(const std::unordered_map<int, ControlConn*>::const_iterator& iter)
{
    ControlConn* ctrlcon = iter->second;
    unregister_control_fd(iter->first, ctrlcon->get_fd());

    if (ctrlcon->is_blocked())
    {
        ctrlcon->remove();
    }
    else
    {
        delete ctrlcon;
    }

    controls.erase(iter);
}

static void delete_control(int fd)
{
    const auto& iter = controls.find(fd);
    if (iter != controls.cend())
        delete_control(iter);
}

static int execute_control_commands(ControlConn *ctrlcon)
{
    int executed = 0;
    if (!ctrlcon)
        return executed;

    executed = ctrlcon->execute_commands();
    if (executed > 0)
    {
        if (ctrlcon->is_local())
            proc_stats.local_commands += executed;
        else
            proc_stats.remote_commands += executed;
    }
    return executed;
}

static void process_pending_control_commands()
{
    for (auto it : controls)
    {
        if (it.second->has_pending_command())
        {
            ControlConn* ctrlcon = it.second;
            execute_control_commands(ctrlcon);
        }
    }
}

static bool process_control_commands(int fd)
{
    const auto iter = controls.find(fd);
    if (iter == controls.cend())
        return false;

    ControlConn* ctrlcon = iter->second;

    int read = ctrlcon->read_commands();
    if (read <= 0)
    {
        if (read < 0)
            delete_control(iter);
        return false;
    }

    int executed = execute_control_commands(ctrlcon);

    if (ctrlcon->is_closed())
        delete_control(iter);

    return (executed > 0);
}

static void clear_controls()
{
    for (const auto& p : controls)
    {
        ControlConn* ctrlcon = p.second;
        unregister_control_fd(p.first, ctrlcon->get_fd());
        delete ctrlcon;
    }
    controls.clear();
}

static void delete_expired_controls()
{
    int fds[MAX_CONTROL_FDS], n=0;
    time_t curr_time = time(nullptr);
    for (const auto& p : controls)
    {
        ControlConn* ctrlcon = p.second;
        if (!ctrlcon->is_local() and (curr_time - ctrlcon->get_touched()) >= MAX_CONTROL_IDLE_TIME)
            fds[n++] = p.first;
    }
    for(int i=0; i<n; i++)
    {
        LogMessage("Control: closing fd=%d that was idle for more than %d seconds.\n", fds[i], MAX_CONTROL_IDLE_TIME);
        delete_control(fds[i]);
    }
}

//-------------------------------------------------------------------------
// Public API
//-------------------------------------------------------------------------

bool ControlMgmt::add_control(int fd, bool local)
{
    auto i = controls.find(fd);
    if (i != controls.cend())
    {
        if (i->second->is_closed())
        {
            delete_control(i);
        }
        else
        {
            WarningMessage("Duplicated control channel file descriptor, fd = %d\n", fd);
            return false;
        }
    }

    if (!register_control_fd(fd))
        return false;

    ControlConn* ctrlcon = new ControlConn(fd, local);
    controls[fd] = ctrlcon;

    return true;
}

ControlConn* ControlMgmt::find_control(const lua_State* L)
{
    for (const auto& p : controls)
    {
        ControlConn* ctrlcon = p.second;
        if (ctrlcon->get_shell()->get_lua() == L)
            return ctrlcon;
    }
    return nullptr;
}

void ControlMgmt::reconfigure_controls()
{
    for (const auto& p : controls)
        p.second->configure();
}

int ControlMgmt::socket_init(const SnortConfig* sc)
{
    if (!init_controls())
        FatalError("Failed to initialize controls.\n");

    int sock_family = setup_socket_family(sc);
    if (sock_family == AF_UNSPEC)
        return -1;

    listener = socket(sock_family, SOCK_STREAM, 0);

    if (listener < 0)
        FatalError("Failed to create control listener: %s\n", get_error(errno));

    // FIXIT-M want to disable time wait
    int on = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (bind(listener, sock_addr, sock_addr_size) < 0)
        FatalError("Failed to bind control listener: %s\n", get_error(errno));

    if (listen(listener, MAX_CONTROL_FDS) < 0)
        FatalError("Failed to start listening on control listener: %s\n", get_error(errno));

    if (!register_control_fd(listener))
        FatalError("Failed to register listener socket.\n");

    return 0;
}

void ControlMgmt::socket_term()
{
    clear_controls();

    if (listener >= 0)
    {
        close(listener);
        listener = -1;
    }

    term_controls();
}

bool ControlMgmt::service_users()
{
    static FdEvents event[MAX_CONTROL_FDS];
    unsigned nevent;

    process_pending_control_commands();

    if (!poll_control_fds(event, nevent))
        return false;

    unsigned serviced = 0;
    for (unsigned i = 0; i < nevent; i++)
    {
        int fd = event[i].fd;
        if (event[i].flag & READY)
        {
            // Process ready descriptors first, even if they're dead, to honor their last request
            if (fd == listener)
            {
                // Got a new connection request, attempt to accept it and store it in controls
                if (accept_conn())
                    serviced++;
            }
            else if (process_control_commands(fd))
                serviced++;
        }
        if (event[i].flag & DEAD)
        {
            delete_control(fd);
            serviced++;
        }
    }

    return (serviced > 0);
}


// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------


#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#include "main/ac_shell_cmd.h"

class ACExample : public AnalyzerCommand
{
    bool execute(Analyzer &, void **) override { return true; }
    const char * stringify() override { return "ACExample"; }
    ~ACExample() override {}
};

TEST_CASE("Do not delete ctrlcon if its in use by another ACShellCmd")
{
    int pipefd[2];
    pipe(pipefd);

    ControlConn* ctrlcon = new ControlConn(pipefd[1], false);

    auto iter = controls.insert({pipefd[1], ctrlcon});

    ACShellCmd* acshell1 = new ACShellCmd(ctrlcon, new ACExample());
    ACShellCmd* acshell2 = new ACShellCmd(ctrlcon, new ACExample());

    delete_control(iter.first);

    delete acshell1;

    CHECK((ctrlcon->is_blocked() == true));
    CHECK((ctrlcon->is_closed() == false));

    delete acshell2;

    close(pipefd[0]);
    close(pipefd[1]);

};

TEST_CASE("Do not unblock ctrlcon if its in use by another ACShellCmd")
{
    int pipefd[2];
    pipe(pipefd);

    ControlConn* ctrlcon = new ControlConn(pipefd[1], false);

    auto iter = controls.insert({pipefd[1], ctrlcon});

    ACShellCmd* acshell1 = new ACShellCmd(ctrlcon, new ACExample());
    ACShellCmd* acshell2 = new ACShellCmd(ctrlcon, new ACExample());

    CHECK((ctrlcon->is_blocked() == true));

    delete acshell1;

    CHECK((ctrlcon->is_blocked() == true));

    delete acshell2;

    CHECK((ctrlcon->is_blocked() == false));

    delete_control(iter.first);

    close(pipefd[0]);
    close(pipefd[1]);

};

#endif
