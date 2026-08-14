//--------------------------------------------------------------------------
// Copyright (C) 2017-2026 Cisco and/or its affiliates. All rights reserved.
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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <cassert>
#include <chrono>
#include <unordered_map>
#include <vector>

#include "log/messages.h"
#include "main.h"
#include "main/shell.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "managers/module_manager.h"
#include "utils/stats.h"
#include "utils/util.h"
#include "utils/util_cstring.h"
#include "helpers/challenge_response_auth.h"

#include "control.h"

using namespace snort;

static constexpr unsigned MAX_CONTROL_FDS = 16;
#ifndef REG_TEST
static constexpr unsigned MAX_CONTROL_IDLE_TIME = 60;
#else
static constexpr unsigned MAX_CONTROL_IDLE_TIME = 5;
#endif

static int listener = -1;
static socklen_t sock_addr_size = 0, my_sock_addr_size = 0;
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
    for (unsigned i = 0; i < npfds; i++)
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

    if (sc->remote_control_port >= 0)
    {
        memset(&in_addr, 0, sizeof(in_addr));

        in_addr.sin_family = AF_INET;
        in_addr.sin_addr.s_addr = htonl(0x7F000001);
        in_addr.sin_port = htons(sc->remote_control_port);
        sock_addr = reinterpret_cast<struct sockaddr*>(&in_addr);
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
        sock_addr = reinterpret_cast<struct sockaddr*>(&unix_addr);
        sock_addr_size = sizeof(unix_addr);
        unlink(fullpath.c_str());
        family = AF_UNIX;
    }
    return family;
}

// cppcheck-suppress constParameterPointer
static bool get_peer_credentials(int fd, uid_t* peer_uid, gid_t* peer_gid)
{
#ifdef __linux__
    struct ucred peer_cred;
    socklen_t len = sizeof(peer_cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer_cred, &len) != 0)
        return false;
    *peer_uid = peer_cred.uid;
    *peer_gid = peer_cred.gid;
    return true;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    return getpeereid(fd, peer_uid, peer_gid) == 0;
#else
    return false;
#endif
}

static void log_peer_info(int fd, const char* action)
{
    if (sock_addr->sa_family == AF_INET)
    {
        struct sockaddr_in* peer_addr = reinterpret_cast<struct sockaddr_in*>(sock_addr);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr->sin_addr, ip_str, sizeof(ip_str));
        LogMessage("Control: %s connection from %s:%u\n",
            action, ip_str, ntohs(peer_addr->sin_port));
    }
    else if (sock_addr->sa_family == AF_INET6)
    {
        struct sockaddr_in6* peer_addr = reinterpret_cast<struct sockaddr_in6*>(sock_addr);
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &peer_addr->sin6_addr, ip_str, sizeof(ip_str));
        LogMessage("Control: %s connection from [%s]:%u\n",
            action, ip_str, ntohs(peer_addr->sin6_port));
    }
    else if (sock_addr->sa_family == AF_UNIX)
    {
        uid_t peer_uid;
        gid_t peer_gid;

        // cppcheck-suppress knownConditionTrueFalse
        if (get_peer_credentials(fd, &peer_uid, &peer_gid))
            LogMessage("Control: %s UNIX socket connection from UID %u, GID %u\n",
                action, peer_uid, peer_gid);
        else
            LogMessage("Control: %s UNIX socket connection\n", action);
    }
}

static bool validate_peer_credentials(int fd, const SnortConfig* sc)
{
    if (sc->control_socket_uid == static_cast<uid_t>(-1)
        && sc->control_socket_gid == static_cast<gid_t>(-1))
        // no socket operations if user has not asked for
        return true;

    uid_t peer_uid;
    gid_t peer_gid;

    // cppcheck-suppress knownConditionTrueFalse
    if (!get_peer_credentials(fd, &peer_uid, &peer_gid))
    {
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        ErrorMessage("Failed to get peer credentials: %s\n", get_error(errno));
        return false;
#else
        // On platforms without peer credential support, allow connection
        // (file permissions still provide protection).
        return true;
#endif
    }

    if (sc->control_socket_uid != static_cast<uid_t>(-1))
    {
        if (peer_uid != sc->control_socket_uid && peer_uid != 0)
        {
            LogMessage("Control: rejected connection from UID %u (expected %u or root)\n",
                peer_uid, sc->control_socket_uid);
            return false;
        }
    }

    if (sc->control_socket_gid != static_cast<gid_t>(-1))
    {
        if (peer_gid != sc->control_socket_gid)
        {
            LogMessage("Control: rejected connection from GID %u (expected %u)\n",
                peer_gid, sc->control_socket_gid);
            return false;
        }
    }

    return true;
}

static bool authenticate_connection(int fd, const SnortConfig* sc)
{
    if (!sc->control_shared_secret || sc->control_shared_secret_len == 0)
        return true;

    // FIXIT-M: refactor to use non-blocking I/O with async authentication
    // Using 1 second timeout as temporary mitigation.
    constexpr int AUTH_TIMEOUT_SEC = 1;
    struct timeval timeout;
    timeout.tv_sec = AUTH_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        ErrorMessage("Control: failed to set authentication timeout: %s\n", get_error(errno));
        return false;
    }

    ChallengeResponseAuth auth(sc->control_shared_secret, sc->control_shared_secret_len);

    const uint8_t* challenge = auth.generate_challenge();
    if (!challenge)
    {
        ErrorMessage("Control: failed to generate authentication challenge\n");
        return false;
    }

    ssize_t bytes_sent = write(fd, challenge, auth.get_challenge_size());
    if (bytes_sent != static_cast<ssize_t>(auth.get_challenge_size()))
    {
        ErrorMessage("Control: failed to send authentication challenge: %s\n", get_error(errno));
        return false;
    }

    // Receive HMAC response from client
    // The SO_RCVTIMEO will cause read() to fail with EAGAIN/EWOULDBLOCK on timeout
    uint8_t client_hmac[ChallengeResponseAuth::HMAC_SIZE];
    size_t total_received = 0;

    while (total_received < sizeof(client_hmac))
    {
        ssize_t bytes = read(fd, client_hmac + total_received, sizeof(client_hmac) - total_received);

        if (bytes < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                log_peer_info(fd, "rejected");
                LogMessage("Control: authentication timeout (%d seconds)\n", AUTH_TIMEOUT_SEC);
                return false;
            }
            log_peer_info(fd, "rejected");
            ErrorMessage("Control: failed to receive authentication response: %s\n", get_error(errno));
            return false;
        }
        else if (bytes == 0)
        {
            log_peer_info(fd, "rejected");
            LogMessage("Control: connection closed during authentication\n");
            return false;
        }

        total_received += bytes;
    }

    if (!auth.verify(client_hmac))
    {
        log_peer_info(fd, "rejected");
        LogMessage("Control: authentication failed - invalid HMAC\n");
        return false;
    }

    log_peer_info(fd, "accepted");
    LogMessage("Control: connection authenticated successfully\n");
    return true;
}

static bool accept_conn()
{
    int fd = accept(listener, sock_addr, &sock_addr_size);
    if (fd < 0)
    {
        ErrorMessage("Failed to accept control socket connection: %s\n", get_error(errno));
        return false;
    }

    const SnortConfig* sc = SnortConfig::get_conf();
    if (sock_addr->sa_family == AF_UNIX && !validate_peer_credentials(fd, sc))
    {
        close(fd);
        return false;
    }

    if (sock_addr->sa_family != AF_UNIX && !authenticate_connection(fd, sc))
    {
        close(fd);
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

    return true;
}

static void delete_control(const std::unordered_map<int, ControlConn*>::const_iterator& iter)
{
    ControlConn* ctrlcon = iter->second;

    int fd = ctrlcon->get_fd();
    if (ctrlcon->is_registered())
    {
        unregister_control_fd(iter->first, fd);
        ctrlcon->mark_unregistered();
    }

    if (ctrlcon->is_blocked())
    {
        ctrlcon->remove();
        return;
    }
    else
    {
        ctrlcon->shutdown();
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
        std::lock_guard<std::mutex> lock(ModuleManager::stats_mutex);
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

    if (ctrlcon->is_removed())
        delete_control(iter);

    return (executed > 0);
}

static void clear_controls()
{
    for (const auto& p : controls)
    {
        ControlConn* ctrlcon = p.second;

        if (ctrlcon->is_registered())
        {
            unregister_control_fd(p.first, ctrlcon->get_fd());
            ctrlcon->mark_unregistered();
        }

        delete ctrlcon;
    }
    controls.clear();
}

static bool is_fd_valid(int fd)
{
    if (fd < 0)
        return false;

    if (fcntl(fd, F_GETFD) == -1)
        return errno != EBADF;

    return true;
}

static void remove_broken_controls()
{
    std::vector<int> fds;
    fds.reserve(controls.size());
    for (const auto& p : controls)
    {
        const ControlConn* ctrlcon = p.second;
        if (ctrlcon && !is_fd_valid(ctrlcon->get_fd()))
            fds.push_back(p.first);
    }

    for (int fd : fds)
        delete_control(fd);
}

static void reap_removed_controls()
{
    std::vector<int> fds;
    fds.reserve(controls.size());
    for (const auto& p : controls)
    {
        const ControlConn* ctrlcon = p.second;
        if (ctrlcon && ctrlcon->is_removed())
            fds.push_back(p.first);
    }

    for (int fd : fds)
        delete_control(fd);
}

[[maybe_unused]] static void delete_expired_controls()
{
    std::vector<int> fds;
    fds.reserve(controls.size());
    time_t curr_time = time(nullptr);
    for (const auto& p : controls)
    {
        const ControlConn* ctrlcon = p.second;
        if (!ctrlcon->is_local() and (curr_time - ctrlcon->get_touched()) >= MAX_CONTROL_IDLE_TIME)
            fds.push_back(p.first);
    }
    for (int fd : fds)
    {
        LogMessage("Control: closing fd=%d that was idle for more than %d seconds.\n", fd, MAX_CONTROL_IDLE_TIME);
        delete_control(fd);
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
        if (i->second->is_removed() || !is_fd_valid(i->second->get_fd()))
        {
            if (i->second->is_blocked())
            {
                WarningMessage("Blocked control channel still present for fd = %d\n", fd);
                return false;
            }
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
    // cppcheck-suppress knownConditionTrueFalse ; control initialization can fail at runtime
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
    my_sock_addr_size = sock_addr_size;
    if (bind(listener, sock_addr, sock_addr_size) < 0)
        FatalError("Failed to bind control listener: %s\n", get_error(errno));

    // Set restrictive permissions on UNIX socket
    if (sock_family == AF_UNIX)
    {
        if (chmod(unix_addr.sun_path, S_IRUSR | S_IWUSR) != 0)
            FatalError("Failed to set permissions on control socket %s: %s\n", unix_addr.sun_path, get_error(errno));
    }

    if (sock_family == AF_INET)
    {
        struct sockaddr_in bound_addr;
        socklen_t bound_len = sizeof(bound_addr);
        if (getsockname(listener, reinterpret_cast<struct sockaddr*>(&bound_addr), &bound_len) == 0)
        {
            unsigned short actual_port = ntohs(bound_addr.sin_port);
            LogMessage("Control: listening on TCP port %u\n", actual_port);
        }
    }
    else if (sock_family == AF_UNIX)
    {
        LogMessage("Control: listening on UNIX socket %s\n", unix_addr.sun_path);
    }

    if (listen(listener, MAX_CONTROL_FDS) < 0)
        FatalError("Failed to start listening on control listener: %s\n", get_error(errno));

    if (!register_control_fd(listener))
        FatalError("Failed to register listener socket.\n");

    return 0;
}

// Helper function to wait for the prompt with a timeout
static bool wait_for_prompt(int fd, const std::string& prompt, int timeout_ms)
{
    char buffer[1024];
    std::string response;
    auto start_time = std::chrono::steady_clock::now();

    while (true)
    {
        ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
        if (bytes < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // Check if the timeout has been exceeded
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start_time);
                if (elapsed.count() >= timeout_ms)
                {
                    return false; // Timeout
                }
                continue; // Retry
            }
            else
            {
                ErrorMessage("Failed to read response: %s\n", get_error(errno));
                return false;
            }
        }
        else if (bytes == 0)
        {
            return false; // Connection closed
        }

        buffer[bytes] = '\0';
        response += buffer;

        // Check if the prompt is found in the response
        if (response.find(prompt) != std::string::npos)
        {
            return true;
        }
    }
}

bool ControlMgmt::send_command_to_socket(const std::string& command)
{
    std::string prompt = get_prompt();
    if (listener < 0)
    {
        ErrorMessage("Listener is not initialized.\n");
        return false;
    }

    int fd = socket(sock_addr->sa_family, SOCK_STREAM, 0);
    if (fd < 0)
    {
        ErrorMessage("Failed to create socket: %s\n", get_error(errno));
        return false;
    }

    if (connect(fd, sock_addr, my_sock_addr_size) >= 0 && wait_for_prompt(fd, prompt, 30) &&
        write(fd, command.c_str(), command.size()) >= 0)
    {
        // Wait for the prompt again to ensure the command was processed
        if (wait_for_prompt(fd, prompt, 90))
        {
            close(fd);
            return true;
        }
    }
    close(fd);
    return false;
}

int ControlMgmt::get_control_port()
{
    if (listener < 0 || sock_addr->sa_family != AF_INET)
        return -1;

    struct sockaddr_in bound_addr;
    socklen_t bound_len = sizeof(bound_addr);
    if (getsockname(listener, reinterpret_cast<struct sockaddr*>(&bound_addr), &bound_len) < 0)
        return -1;

    return ntohs(bound_addr.sin_port);
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

    reap_removed_controls();

    process_pending_control_commands();

    remove_broken_controls();

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
    bool execute(Analyzer &) override { return true; }
    const char * stringify() override { return "ACExample"; }
    ~ACExample() override {}
};

TEST_CASE("Do not delete ctrlcon if its in use by another ACShellCmd")
{
    init_controls();
    int pipefd[2];
    pipe(pipefd);

    ControlConn* ctrlcon = new ControlConn(pipefd[1], false);

    auto iter = controls.insert({pipefd[1], ctrlcon});
    CHECK(true == register_control_fd(pipefd[1]));

    ACShellCmd* acshell1 = new ACShellCmd(ctrlcon, new ACExample());
    ACShellCmd* acshell2 = new ACShellCmd(ctrlcon, new ACExample());

    delete_control(iter.first);

    delete acshell1;

    CHECK(true == ctrlcon->is_blocked());
    CHECK(true == ctrlcon->is_removed());
    CHECK(controls.find(pipefd[1]) != controls.end());

    delete acshell2;

    reap_removed_controls();
    CHECK(controls.find(pipefd[1]) == controls.end());

    close(pipefd[0]);
    term_controls();
};

TEST_CASE("Do not unblock ctrlcon if its in use by another ACShellCmd")
{
    init_controls();
    int pipefd[2];
    pipe(pipefd);

    ControlConn* ctrlcon = new ControlConn(pipefd[1], false);

    auto iter = controls.insert({pipefd[1], ctrlcon});
    CHECK(true == register_control_fd(pipefd[1]));

    ACShellCmd* acshell1 = new ACShellCmd(ctrlcon, new ACExample());
    ACShellCmd* acshell2 = new ACShellCmd(ctrlcon, new ACExample());

    CHECK(true == ctrlcon->is_blocked());

    delete acshell1;

    CHECK(true == ctrlcon->is_blocked());

    delete acshell2;

    CHECK(false == ctrlcon->is_blocked());

    delete_control(iter.first);

    close(pipefd[0]);
    term_controls();
};

TEST_CASE("reap_removed_controls deletes unblocked removed controls")
{
    init_controls();
    int pipefd[2];
    pipe(pipefd);

    ControlConn* ctrlcon = new ControlConn(pipefd[1], false);
    controls.insert({pipefd[1], ctrlcon});
    CHECK(true == register_control_fd(pipefd[1]));

    ctrlcon->remove();
    reap_removed_controls();

    CHECK(controls.find(pipefd[1]) == controls.end());
    close(pipefd[0]);
    term_controls();
}

TEST_CASE("reap_removed_controls defers blocked controls deletion until unblocked")
{
    init_controls();
    int pipefd[2];
    pipe(pipefd);

    ControlConn* ctrlcon = new ControlConn(pipefd[1], false);
    controls.insert({pipefd[1], ctrlcon});
    CHECK(true == register_control_fd(pipefd[1]));

    ACShellCmd* acshell = new ACShellCmd(ctrlcon, new ACExample());
    ctrlcon->remove();

    reap_removed_controls();

    CHECK(controls.find(pipefd[1]) != controls.end());
    CHECK(true == ctrlcon->is_removed());
    CHECK(true == ctrlcon->is_blocked());

    delete acshell;
    CHECK(false == ctrlcon->is_blocked());

    reap_removed_controls();
    CHECK(controls.find(pipefd[1]) == controls.end());

    close(pipefd[0]);
    term_controls();
}

TEST_CASE("blocked control keeps fd open until command completes")
{
    init_controls();
    int pipefd[2];
    pipe(pipefd);

    ControlConn* ctrlcon = new ControlConn(pipefd[1], false);
    auto iter = controls.insert({pipefd[1], ctrlcon});
    CHECK(true == register_control_fd(pipefd[1]));

    ACShellCmd* acshell = new ACShellCmd(ctrlcon, new ACExample());
    delete_control(iter.first);

    CHECK(true == ctrlcon->is_blocked());
    CHECK(true == ctrlcon->is_removed());
    CHECK(write(pipefd[1], "x", 1) == 1);

    delete acshell;
    reap_removed_controls();
    CHECK(write(pipefd[1], "x", 1) == -1);
    CHECK(errno == EBADF);

    close(pipefd[0]);
    term_controls();
}

#endif
