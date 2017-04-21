//--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifndef CONTROL_H
#define CONTROL_H

#include "main/snort_types.h"

class ControlConn
{
public:
    ControlConn(int fd, bool local_control);
    ~ControlConn();

    int get_fd() { return fd; }
    class Shell* get_shell() { return sh; }
    bool is_local_control() { return local_control; }
    void configure();
private:
    int fd = -1;
    bool local_control = false;
    class Shell *sh;
};

#endif

