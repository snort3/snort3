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
// control_mgmt.h author Bhagya Tholpady <bbantwal@cisco.com>
//
// This provides functions to create and control remote/local connections,
// socket creation/deletion/management functions, and shell commands used by the analyzer.

#ifndef AC_SHELL_CMD_H
#define AC_SHELL_CMD_H

#include "main/analyzer.h"
#include "main/analyzer_command.h"

class ACShellCmd : public snort::AnalyzerCommand
{
public:
    ACShellCmd() = delete;
    ACShellCmd(int fd, snort::AnalyzerCommand* ac_cmd);
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return ac->stringify(); }
    ~ACShellCmd() override;

private:
    int control_fd = -1;
    snort::AnalyzerCommand* ac;
};

#endif
