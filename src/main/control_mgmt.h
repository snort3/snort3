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
// control_mgmt.h author Bhagya Tholpady <bbantwal@cisco.com>
//
// This provides functions to create and control remote/local connections,
// socket creation/deletion/management functions, and shell commands used by the analyzer.

#ifndef CONTROL_MGMT_H
#define CONTROL_MGMT_H

#include <vector>

#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/snort_types.h"
#include "utils/util.h"

class ControlConn;

class ControlMgmt
{
public:
    static void add_control(int fd, bool local_control);
    static void delete_control(int fd);
    static void delete_controls();
    static ControlConn* find_control(int fd);
    static void reconfigure_controls();

    static bool find_control(int fd, std::vector<ControlConn*>::iterator& control);
    static void delete_control(std::vector<ControlConn*>::iterator& control);

    static int socket_init();
    static int socket_term();
    static int socket_conn();

    static bool process_control_commands(int& current_fd, class Request*& current_request);
    static bool service_users(int& current_fd, class Request*& current_request);
private:
    static int setup_socket_family();
};

class ACShellCmd : public AnalyzerCommand
{
public:
    ACShellCmd() = delete;
    ACShellCmd(int fd, AnalyzerCommand* ac_cmd);
    void execute(Analyzer&) override;
    const char* stringify() override { return ac->stringify(); }
    ~ACShellCmd() override;
private:
    int control_fd = -1;
    AnalyzerCommand* ac;
};

#endif
