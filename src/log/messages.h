//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
#include <cstdarg>
#include <string>
#include <ctime>

#include "main/snort_types.h"

#define LOG_DIV "--------------------------------------------------"

#ifndef __GNUC__
#define __attribute__(x)  /*NOTHING*/
#endif

#define STD_BUF 1024

enum WarningGroup
{
    WARN_DAQ, WARN_CONF, WARN_CONF_STRICT, WARN_VARS,
    WARN_SYMBOLS, WARN_SCRIPTS, WARN_HOSTS, WARN_RULES,
    WARN_FLOWBITS, WARN_PLUGINS,
    WARN_MAX
};

namespace snort
{
SO_PUBLIC void ParseWarning(WarningGroup, const char*, ...) __attribute__((format (printf, 2, 3)));
SO_PUBLIC void ParseError(const char*, ...) __attribute__((format (printf, 1, 2)));
SO_PUBLIC void ReloadError(const char*, ...) __attribute__((format (printf, 1, 2)));
[[noreturn]] SO_PUBLIC void ParseAbort(const char*, ...) __attribute__((format (printf, 1, 2)));

SO_PUBLIC void LogMessage(const char*, va_list& ap);
SO_PUBLIC void LogMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
SO_PUBLIC void LogMessage(FILE*, const char*, ...) __attribute__((format (printf, 2, 3)));
SO_PUBLIC void WarningMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
SO_PUBLIC void WarningMessage(const char*, va_list& ap);
SO_PUBLIC void ErrorMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
SO_PUBLIC void ErrorMessage(const char*, va_list& ap);

class SO_PUBLIC ConfigLogger final
{
public:
    ConfigLogger() = delete;

    static void log_option(const char* caption);

    static bool log_flag(const char* caption, bool flag, bool subopt = false);

    static void log_limit(const char* caption, int val, int unlim, bool subopt = false);
    static void log_limit(const char* caption, unsigned int val, unsigned int unlim, bool subopt = false);
    static void log_limit(const char* caption, long val, int unlim, bool subopt = false);
    static void log_limit(const char* caption, unsigned long val, unsigned int unlim, bool subopt = false);
    static void log_limit(const char* caption, long long val, int unlim, bool subopt = false);
    static void log_limit(const char* caption, unsigned long long val, unsigned int unlim, bool subopt = false);

    static void log_limit(const char* caption, int val, int unlim, int disable, bool subopt = false);
    static void log_limit(const char* caption, unsigned int val, unsigned int unlim, unsigned int disable, bool subopt = false);
    static void log_limit(const char* caption, long val, int unlim, int disable, bool subopt = false);
    static void log_limit(const char* caption, unsigned long val, unsigned int unlim, unsigned int disable, bool subopt = false);
    static void log_limit(const char* caption, long long val, int unlim, int disable, bool subopt = false);
    static void log_limit(const char* caption, unsigned long long val, unsigned int unlim, unsigned int disable, bool subopt = false);

    static void log_value(const char* caption, int n, const char* descr, bool subopt = false);

    static void log_value(const char* caption, int n, bool subopt = false);
    static void log_value(const char* caption, unsigned int n, bool subopt = false);
    static void log_value(const char* caption, long n, bool subopt = false);
    static void log_value(const char* caption, unsigned long n, bool subopt = false);
    static void log_value(const char* caption, long long n, bool subopt = false);
    static void log_value(const char* caption, unsigned long long n, bool subopt = false);
    static void log_value(const char* caption, double n, bool subopt = false);
    static void log_value(const char* caption, const char* str, bool subopt = false);

    static void log_list(const char* caption, const char* list, const char* prefix = " ", bool subopt = false);
    static void log_list(const char* list);
private:
    static constexpr int indention = 25;
    static constexpr int max_line_len = 75;
};

// FIXIT-RC do not call FatalError() during runtime
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

