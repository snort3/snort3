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
// control_mgmt.h author Bhagya Tholpady <bbantwal@cisco.com>
//                author Devendra Dahiphale <ddahipha@cisco.com>
//                author Michael Altizer <mialtize@cisco.com>
// This provides functions to create and control remote/local connections,
// socket creation/deletion/management functions, and shell commands used by the analyzer.

#ifndef CONTROL_MGMT_H
#define CONTROL_MGMT_H

class ControlConn;
struct lua_State;

namespace snort
{
struct SnortConfig;
}

class ControlMgmt
{
public:
    static bool add_control(int fd, bool local_control);
    static void reconfigure_controls();

    static int socket_init(const snort::SnortConfig*);
    static void socket_term();

    static ControlConn* find_control(const lua_State*);

    static bool service_users();
};

#endif
