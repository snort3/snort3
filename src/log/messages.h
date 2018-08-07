//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef MESSAGES_H
#define MESSAGES_H

#include <arpa/inet.h>
#include <cstdio>
#include <ctime>

#include "main/snort_types.h"

#define LOG_DIV "--------------------------------------------------"

#ifndef __GNUC__
#define __attribute__(x)  /*NOTHING*/
#endif

#define STD_BUF 1024

enum WarningGroup
{
    WARN_DAQ, WARN_CONF, WARN_VARS, WARN_SYMBOLS, WARN_SCRIPTS,
    WARN_HOSTS, WARN_RULES, WARN_FLOWBITS, WARN_PLUGINS,
#ifdef PIGLET
    WARN_PIGLET,
#endif
    WARN_MAX
};

void reset_parse_errors();
unsigned get_parse_errors();
unsigned get_parse_warnings();

namespace snort
{
SO_PUBLIC void ParseMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
SO_PUBLIC void ParseWarning(WarningGroup, const char*, ...) __attribute__((format (printf, 2, 3)));
SO_PUBLIC void ParseError(const char*, ...) __attribute__((format (printf, 1, 2)));
[[noreturn]] SO_PUBLIC void ParseAbort(const char*, ...) __attribute__((format (printf, 1, 2)));

SO_PUBLIC void LogMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
SO_PUBLIC void LogMessage(FILE* fh, const char*, ...) __attribute__((format (printf, 2, 3)));
SO_PUBLIC void WarningMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
SO_PUBLIC void ErrorMessage(const char*, ...) __attribute__((format (printf, 1, 2)));

// FIXIT-M do not call FatalError() during runtime
[[noreturn]] SO_PUBLIC void FatalError(const char*, ...) __attribute__((format (printf, 1, 2)));

NORETURN_ASSERT void log_safec_error(const char*, void*, int);

class Dumper
{
public:
    Dumper(const char* s = nullptr, unsigned n = 3)
    {
        max = n; idx = 0;
        if ( s )
            LogMessage("%s\n", s);
    }

    ~Dumper()
    {
        if ( idx % max )
            LogMessage("\n");
    }

    void dump(const char* s, unsigned v = 0)
    {
        const char* eol = !(++idx % max) ? "\n" : "";
        LogMessage("    %18.18s(v%u)%s", s, v, eol);
    }

    void dump(const char* s, const char* t)
    {
        LogMessage("%s::%s\n", s, t);
    }

private:
    unsigned max;
    unsigned idx;
};
}

#endif

