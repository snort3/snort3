//--------------------------------------------------------------------------
// Copyright (C) 2017-2021 Cisco and/or its affiliates. All rights reserved.
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

#include <cstdarg>
#include <ctime>
#include <queue>
#include <string>

#include "main/snort_types.h"

struct lua_State;

class ControlConn
{
public:
    ControlConn(int fd, bool local);
    ~ControlConn();

    ControlConn(const ControlConn&) = delete;
    ControlConn& operator=(const ControlConn&) = delete;

    int get_fd() const { return fd; }
    class Shell* get_shell() const { return shell; }

    void block();
    void unblock();
    void remove();

    bool is_blocked() const { return blocked; }
    bool is_closed() const { return (fd == -1); }
    bool is_removed() const { return removed; }
    bool has_pending_command() const { return !pending_commands.empty(); }
    time_t get_touched() const;
    std::string get_current_command() const { return pending_commands.front(); }

    void configure() const;
    int read_commands();
    int execute_commands();
    void shutdown();

    SO_PUBLIC bool is_local() const { return local; }
    SO_PUBLIC bool respond(const char* format, ...) __attribute__((format (printf, 2, 3)));
    SO_PUBLIC static ControlConn* query_from_lua(const lua_State*);

private:
    bool respond(const char* format, va_list& ap);
    bool show_prompt();
    void touch();

private:
    std::queue<std::string> pending_commands;
    std::string next_command;
    class Shell *shell;
    int fd;
    bool local = false;
    bool blocked = false;
    bool removed = false;
    time_t touched;
};

#define LogRespond(cn, ...)       if (cn) cn->respond(__VA_ARGS__); else LogMessage(__VA_ARGS__)
#define LogfRespond(cn, fh, ...)  if (cn) cn->respond(__VA_ARGS__); else LogMessage(fh, __VA_ARGS__)

#endif
