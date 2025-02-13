//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "control/control.h"

ACShellCmd::ACShellCmd(ControlConn* conn, AnalyzerCommand* ac) : AnalyzerCommand(conn), ac(ac)
{
    assert(ac);

    if (ctrlcon)
        ctrlcon->block();
    ControlConn::increment_pending_cmds_count();
}

bool ACShellCmd::execute(Analyzer& analyzer, void** state)
{
    ctrlcon->set_user_network_policy();
    return ac->execute(analyzer, state);
}

ACShellCmd::~ACShellCmd()
{
    delete ac;
    ControlConn::decrement_pending_cmds_count();

    if (ctrlcon)
    {
        ctrlcon->unblock();
        if (ctrlcon->is_removed() and !ctrlcon->is_blocked())
            delete ctrlcon;
    }
}
