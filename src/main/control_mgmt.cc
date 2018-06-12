//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "control_mgmt.h"

#include <netinet/in.h>
#include <sys/un.h>

#include <algorithm>
#include <cassert>

#include "log/messages.h"
#include "utils/stats.h"
#include "control.h"
#include "request.h"
#include "snort_config.h"

using namespace snort;
using namespace std;

static int listener = -1;
static socklen_t sock_addr_size = 0;
static struct sockaddr* sock_addr = nullptr;
static struct sockaddr_in in_addr;
static struct sockaddr_un unix_addr;
static fd_set inputs;
static std::vector<ControlConn*> controls;

void ControlMgmt::add_control(int fd, bool local)
{
    controls.push_back(new ControlConn(fd, local));
}

bool ControlMgmt::find_control(int fd, std::vector<ControlConn*>::iterator& control)
{
    control = std::find_if(controls.begin(), controls.end(),
                [=](const ControlConn* c) { return c->get_fd() == fd; });

    if(control != controls.end())
        return true;
    else
        return false;
}

ControlConn* ControlMgmt::find_control(int fd)
{
    std::vector<ControlConn*>::iterator it;

    ControlConn* control = find_control(fd, it) ? (*it) : nullptr;
    return control;
}

void ControlMgmt::delete_control(std::vector<ControlConn*>::iterator& control)
{
    delete *control;
    control = controls.erase(control);
}

void ControlMgmt::delete_control(int fd)
{
    std::vector<ControlConn*>::iterator control;
    if ( find_control(fd, control) )
        delete_control(control);
}

void ControlMgmt::reconfigure_controls()
{
    for ( auto control : controls )
    {
        control->configure();
    }
}

void ControlMgmt::delete_controls()
{
    for ( auto control : controls )
    {
        delete control;
    }
    controls.clear();
}

//-------------------------------------------------------------------------
// socket foo
//-------------------------------------------------------------------------
// FIXIT-M make these non-blocking
// FIXIT-M bind to configured ip including INADDR_ANY
// (default is loopback if enabled)

int ControlMgmt::setup_socket_family()
{
    int family = AF_UNSPEC;
    if ( SnortConfig::get_conf()->remote_control_port )
    {
        memset(&in_addr, 0, sizeof(in_addr));

        in_addr.sin_family = AF_INET;
        in_addr.sin_addr.s_addr = htonl(0x7F000001);
        in_addr.sin_port = htons(SnortConfig::get_conf()->remote_control_port);
        sock_addr = (struct sockaddr*)&in_addr;
        sock_addr_size = sizeof(in_addr);
        family = AF_INET;
    }
    else if ( !SnortConfig::get_conf()->remote_control_socket.empty() )
    {
        std::string fullpath;
        const char* path_sep = strrchr(SnortConfig::get_conf()->remote_control_socket.c_str(), '/');
        if (path_sep != nullptr)
            fullpath = SnortConfig::get_conf()->remote_control_socket;
        else
            get_instance_file(fullpath, SnortConfig::get_conf()->remote_control_socket.c_str());

        memset(&unix_addr, 0, sizeof(unix_addr));
        unix_addr.sun_family = AF_UNIX;
        strncpy(unix_addr.sun_path, fullpath.c_str(), sizeof(unix_addr.sun_path)-1);
        sock_addr = (struct sockaddr*)&unix_addr;
        sock_addr_size = sizeof(unix_addr);
        unlink(fullpath.c_str());
        family = AF_UNIX;
    }

    return family;
}

int ControlMgmt::socket_init()
{
    int sock_family = setup_socket_family();

    if ( sock_family == AF_UNSPEC )
        return -1;

    listener = socket(sock_family, SOCK_STREAM, 0);

    if (listener < 0)
        FatalError("socket failed: %s\n", get_error(errno));

    // FIXIT-M want to disable time wait
    int on = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if ( ::bind(listener, sock_addr, sock_addr_size) < 0 )
        FatalError("bind failed: %s\n", get_error(errno));

    // FIXIT-M configure max conns
    if ( listen(listener, 0) < 0 )
        FatalError("listen failed: %s\n", get_error(errno));

    return 0;
}

int ControlMgmt::socket_term()
{
    delete_controls();

    if ( listener >= 0 )
        close(listener);

    listener = -1;

    return 0;
}

int ControlMgmt::socket_conn()
{
    int remote_control = accept(listener, sock_addr, &sock_addr_size);

    if ( remote_control < 0 )
        return -1;

    add_control(remote_control, false);

    // FIXIT-L authenticate, use ssl ?
    return 0;
}

bool ControlMgmt::process_control_commands(int& current_fd, Request*& current_request)
{
    bool ret = false;

    for(std::vector<ControlConn*>::iterator control =
            controls.begin(); control != controls.end();)
    {
        int fd = (*control)->get_fd();
        if ( FD_ISSET(fd, &inputs) )
        {
            Request* old_request = current_request;
            fd = (*control)->shell_execute(current_fd, current_request);
            current_fd = -1;
            current_request = old_request;
            if( fd < 0 )
            {
                delete_control(control);
                ret = false;
                continue;
            }
            else
            {
                if ( (*control)->is_local_control() )
                    proc_stats.local_commands++;
                else
                    proc_stats.remote_commands++;
                ret = true;
            }
        }
        ++control;
    }
    return ret;
}

bool ControlMgmt::service_users(int& current_fd, Request*& current_request)
{
    FD_ZERO(&inputs);
    int max_fd = -1;
    bool ret = false;

    for ( auto control : controls )
    {
        int fd = control->get_fd();
        if ( fd >= 0 and !control->is_blocked() )
        {
            FD_SET(fd, &inputs);
            if ( fd > max_fd )
                max_fd = fd;
        }
    }
    if ( listener >= 0 )
    {
        FD_SET(listener, &inputs);
        if ( listener > max_fd )
            max_fd = listener;
    }

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if ( select(max_fd+1, &inputs, nullptr, nullptr, &timeout) > 0 )
    {
        ret = process_control_commands(current_fd, current_request);

        if ( listener >= 0 )
        {
            if ( FD_ISSET(listener, &inputs) )
            {
                if ( !socket_conn() )
                {
                    ret = true;
                }
            }
        }
    }
    return ret;
}

ACShellCmd::ACShellCmd(int fd, AnalyzerCommand *ac) : ac(ac)
{
    assert(ac);
    ControlConn* control = (fd >= 0)? (ControlMgmt::find_control(fd) ) : nullptr;

    if( control )
    {
        control->block();
        control_fd = fd;
    }
}

void ACShellCmd::execute(Analyzer& analyzer)
{
    ControlConn* control = (control_fd >= 0)? (ControlMgmt::find_control(control_fd) ) : nullptr;

    if( control )
    {
        if ( !control->send_queued_response() )
        {
            control_fd = -1;
            return;
        }
    }

    ac->execute(analyzer);
}

ACShellCmd::~ACShellCmd()
{
    delete ac;
    ControlConn* control = (control_fd >= 0)? (ControlMgmt::find_control(control_fd) ) : nullptr;

    if( control )
        control->unblock();
}
