//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// analyzer.h author Russ Combs <rucombs@cisco.com>

#ifndef ANALYZER_H
#define ANALYZER_H

// Analyzer provides the packet acquisition and processing loop.  Since it
// runs in a different thread, it also provides a command facility so that
// to control the thread and swap configuration.

#include <atomic>
#include <string>

enum AnalyzerCommand
{
    AC_NONE,
    AC_START,
    AC_RUN,
    AC_STOP,
    AC_PAUSE,
    AC_RESUME,
    AC_ROTATE,
    AC_SWAP,
    AC_MAX = AC_SWAP
};

class Swapper;
class SFDAQInstance;

class Analyzer
{
public:
    enum class State {
        NEW,
        INITIALIZED,
        STARTED,
        RUNNING,
        PAUSED,
        STOPPED
    };
    Analyzer(unsigned id, const char* source);

    void operator()(Swapper*);

    State get_state() { return state; }
    const char* get_state_string();
    const char* get_source() { return source.c_str(); }

    // FIXIT-M add asynchronous response too
    AnalyzerCommand get_current_command() { return command; }
    void execute(AnalyzerCommand);

    void set_config(Swapper* ps) { swap = ps; }
    bool swap_pending() { return command == AC_SWAP; }
    bool requires_privileged_start() { return privileged_start; }

    static const char* get_command_string(AnalyzerCommand ac);

private:
    void analyze();
    bool handle_command();
    void set_state(State);

private:
    std::atomic<State> state;
    std::atomic<AnalyzerCommand> command;
    std::atomic<bool> privileged_start;

    unsigned id;

    std::string source;
    Swapper* swap;
    SFDAQInstance* daq_instance;
};

#endif

