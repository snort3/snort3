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
// control.h author Bhagya Tholpady <bbantwal@cisco.com>
//
// Header file defining control class used for remote and local connections.
// Each control class has a request and shell associated with it.

#ifndef CONTROL_H
#define CONTROL_H

#include "main/snort_types.h"

class ControlConn
{
public:
    ControlConn(int fd, bool local_control = false);
    ~ControlConn();

    ControlConn(const ControlConn&) = delete;
    ControlConn& operator=(const ControlConn&) = delete;

    int get_fd() const { return fd; }
    class Shell* get_shell() const { return sh; }
    class Request* get_request() const { return request; }
    bool is_local_control() const { return local_control; }

    void block();
    void unblock();
    bool send_queued_response();
    bool is_blocked() const { return blocked; }

    void configure() const;
    int shell_execute(int& current_fd, Request*& current_request);
    bool show_prompt() const;

private:
    int fd;
    bool blocked = false;
    bool local_control;
    class Shell *sh;
    class Request* request;
};

#endif

