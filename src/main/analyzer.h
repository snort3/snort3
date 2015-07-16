//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_types.h"

enum AnalyzerCommand
{
    AC_NONE,
    AC_STOP,
    AC_PAUSE,
    AC_RESUME,
    AC_ROTATE,
    AC_SWAP,
    AC_MAX
};

class Swapper;

class Analyzer
{
public:
    Analyzer(const char* source);

    void operator()(unsigned, Swapper*);

    bool is_done() { return done; }
    uint64_t get_count() { return count; }
    const char* get_source() { return source; }

    // FIXIT-M add asynchronous response too
    bool execute(AnalyzerCommand);

    void set_config(Swapper* ps) { swap = ps; }
    bool swap_pending() { return command == AC_SWAP; }

private:
    void analyze();
    bool handle(AnalyzerCommand);

private:
    bool done;
    uint64_t count;
    const char* source;
    volatile AnalyzerCommand command;
    Swapper* swap;
    void* daqh;
};

#endif

