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

#ifndef LOG_STATS_H
#define LOG_STATS_H

// used for logging pegs

#include <cstdint>
#include <cstdio>

#include "main/snort_types.h"

class ControlConn;

namespace snort
{
void set_log_conn(ControlConn*);

SO_PUBLIC void LogLabel(const char*, FILE* = stdout);
SO_PUBLIC void LogText(const char*, FILE* = stdout);
SO_PUBLIC void LogValue(const char*, const char*, FILE* = stdout);
SO_PUBLIC void LogCount(const char*, uint64_t, FILE* = stdout);

SO_PUBLIC void LogStat(const char*, uint64_t n, uint64_t tot, FILE* = stdout);
SO_PUBLIC void LogStat(const char*, double, FILE* = stdout);
}

#endif

