//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
// ac_shell_cmd.h author Bhagya Tholpady <bbantwal@cisco.com>
//
// This provides functions to create and control remote/local connections,
// socket creation/deletion/management functions, and shell commands used by the analyzer.

#ifndef AC_SHELL_CMD_H
#define AC_SHELL_CMD_H

#include "main/analyzer.h"
#include "main/analyzer_command.h"

class ControlConn;

class ACShellCmd : public snort::AnalyzerCommand
{
public:
    ACShellCmd() = delete;
    ACShellCmd(ControlConn*, snort::AnalyzerCommand*);
    bool execute(Analyzer&, void**) override;
    bool need_update_reload_id() const override
    { return ac->need_update_reload_id(); }
    const char* stringify() override { return ac->stringify(); }
    ~ACShellCmd() override;

private:
    snort::AnalyzerCommand* ac;
};

#endif
