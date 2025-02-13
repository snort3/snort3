//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "log_stats.h"

#include "control/control.h"

#include "messages.h"

//using namespace snort;

//-------------------------------------------------------------------------

static THREAD_LOCAL ControlConn* s_ctrlcon = nullptr;

void snort::set_log_conn(ControlConn* cc)
{ s_ctrlcon = cc; }

//-------------------------------------------------------------------------

#define STATS_SEPARATOR \
    "--------------------------------------------------"

static inline void LogSeparator(FILE* fh = stdout)
{
    LogfRespond(s_ctrlcon, fh, "%s\n", STATS_SEPARATOR);
}

static double CalcPct(uint64_t cnt, uint64_t total)
{
    double pct = 0.0;

    if (total == 0.0)
    {
        pct = (double)cnt;
    }
    else
    {
        pct = (double)cnt / (double)total;
    }

    pct *= 100.0;

    return pct;
}

//-------------------------------------------------------------------------

void snort::LogText(const char* s, FILE* fh)
{
    LogfRespond(s_ctrlcon, fh, "%s\n", s);
}

void snort::LogLabel(const char* s, FILE* fh)
{
    if ( *s == ' ' )
    {
        LogfRespond(s_ctrlcon, fh, "%s\n", s);
    }
    else
    {
        LogSeparator(fh);
        LogfRespond(s_ctrlcon, fh, "%s\n", s);
    }
}

void snort::LogValue(const char* s, const char* v, FILE* fh)
{
    LogfRespond(s_ctrlcon, fh, "%25.25s: %s\n", s, v);
}

void snort::LogCount(const char* s, uint64_t c, FILE* fh)
{
    if ( c )
    {
        LogfRespond(s_ctrlcon, fh, "%25.25s: " STDu64 "\n", s, c);
    }
}

void snort::LogStat(const char* s, uint64_t n, uint64_t tot, FILE* fh)
{
    if ( n )
    {
        LogfRespond(s_ctrlcon, fh, "%25.25s: " FMTu64("-12") "\t(%7.3f%%)\n", s, n, CalcPct(n, tot));
    }
}

void snort::LogStat(const char* s, double d, FILE* fh)
{
    if ( d )
    {
        LogfRespond(s_ctrlcon, fh, "%25.25s: %g\n", s, d);
    }
}

