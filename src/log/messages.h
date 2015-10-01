//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "main/snort_types.h"
#include "sfip/sfip_t.h"

#define LOG_DIV "--------------------------------------------------"

#ifndef __GNUC__
#define __attribute__(x)  /*NOTHING*/
#endif
SO_PUBLIC void LogMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
SO_PUBLIC void WarningMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
SO_PUBLIC void ErrorMessage(const char*, ...) __attribute__((format (printf, 1, 2)));

struct ThrottleInfo
{
    time_t lastUpdate;
    /*Within this duration (in seconds), maximal one distinct message is logged*/
    uint32_t duration_to_log;
    uint64_t count;
};

void ErrorMessageThrottled(ThrottleInfo*,const char*, ...) __attribute__((format (printf, 2, 3)));

// FIXIT-M do not call FatalError() during runtime
NORETURN void FatalError(const char*, ...) __attribute__((format (printf, 1, 2)));

SO_PUBLIC void PrintPacketData(const uint8_t*, const uint32_t);
SO_PUBLIC char* ObfuscateIpToText(const sfip_t*);

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

#endif

