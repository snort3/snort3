//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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
// ac_shell_cmd.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ac_shell_cmd.h"

#include <cassert>

#include "control_mgmt.h"
#include "control.h"

ACShellCmd::ACShellCmd(int fd, AnalyzerCommand *ac) : ac(ac)
{
    assert(ac);

    ControlConn* control_conn = ControlMgmt::find_control(fd);

    if( control_conn )
    {
        control_conn->block();
        control_fd = fd;
    }
}

bool ACShellCmd::execute(Analyzer& analyzer, void** state)
{
    ControlConn* control_conn = ControlMgmt::find_control(control_fd);

    if( control_conn )
        control_conn->send_queued_response();

    return ac->execute(analyzer, state);
}

ACShellCmd::~ACShellCmd()
{
    delete ac;
    ControlConn* control = ControlMgmt::find_control(control_fd);

    if( control )
    {
        control->send_queued_response();
        control->unblock();
    }
}
