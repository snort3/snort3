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

#include "control.h"

#include "main.h"
#include "managers/module_manager.h"
#include "utils/util.h"

#include "control_mgmt.h"
#include "request.h"
#include "shell.h"

using namespace std;

//------------------------------------------------------------------------
// control channel class
// -----------------------------------------------------------------------

ControlConn::ControlConn(int i, bool local)
{
    fd = i;
    local_control = local;
    sh = new Shell;
    request = new Request(fd);
    configure();
    show_prompt();
}

ControlConn::~ControlConn()
{
    if( !local_control )
        close(fd);
    delete sh;
    delete request;
}

void ControlConn::configure() const
{
    ModuleManager::load_commands(sh);
}

int ControlConn::shell_execute(int& current_fd, Request*& current_request)
{
    if ( !request->read(fd) )
        return fd;

    current_fd = fd;
    current_request = request;

    std::string rsp;
    sh->execute(request->get(), rsp);

    if ( !rsp.empty() and !is_blocked() )
        request->respond(rsp.c_str());

    if ( fd >= 0 and !is_blocked() )
        show_prompt();

    return fd;
}

void ControlConn::block()
{
    blocked = true;
}

void ControlConn::unblock()
{
    blocked = false;
    if ( !show_prompt() )
        ControlMgmt::delete_control(fd);
}

bool ControlConn::send_queued_response()
{
    if ( !request->send_queued_response() )
    {
        ControlMgmt::delete_control(fd);
        return false;
    }
    return true;
}

// FIXIT-L would like to flush prompt w/o \n
bool ControlConn::show_prompt() const
{
    std::string s = get_prompt();
    s += "\n";
    return request->write_response(s.c_str());
}
