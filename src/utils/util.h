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

#ifndef UTIL_H
#define UTIL_H

// Miscellaneous functions and macros
// FIXIT-L this needs to be refactored and stripped of cruft

#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>

#include "main/snort_types.h"

#define TIMEBUF_SIZE 26

#define SECONDS_PER_DAY  86400  /* number of seconds in a day  */
#define SECONDS_PER_HOUR  3600  /* number of seconds in a hour */
#define SECONDS_PER_MIN     60     /* number of seconds in a minute */

#define COPY4(x, y) \
    x[0] = (y)[0]; (x)[1] = (y)[1]; (x)[2] = (y)[2]; (x)[3] = (y)[3];

#define COPY16(x,y) \
    x[0] = (y)[0]; (x)[1] = (y)[1]; (x)[2] = (y)[2]; (x)[3] = (y)[3]; \
    (x)[4] = (y)[4]; (x)[5] = (y)[5]; (x)[6] = (y)[6]; (x)[7] = (y)[7]; \
    (x)[8] = (y)[8]; (x)[9] = (y)[9]; (x)[10] = (y)[10]; (x)[11] = (y)[11]; \
    (x)[12] = (y)[12]; (x)[13] = (y)[13]; (x)[14] = (y)[14]; (x)[15] = (y)[15];

// FIXIT-M provide getter function to for standardized access into the protocol_names array
SO_PUBLIC extern char** protocol_names;

void StoreSnortInfoStrings();
int DisplayBanner();
int gmt2local(time_t);
void ts_print(register const struct timeval*, char*);
std::string read_infile(const char* key, const char* fname);
void CleanupProtoNames();
void CreatePidFile(pid_t);
void ClosePidFile();
bool SetUidGid(int, int);
void InitGroups(int, int);
bool EnterChroot(std::string& root_dir, std::string& log_dir);
void InitProtoNames();

#if defined(NOCOREFILE)
void SetNoCores();
#endif

SO_PUBLIC char* snort_strdup(const char*);
SO_PUBLIC char* snort_strndup(const char*, size_t);

inline void* snort_alloc(size_t sz)
{ return new uint8_t[sz]; }

inline void* snort_alloc(size_t num, size_t sz)
{ return snort_alloc(num * sz); }

inline void* snort_calloc(size_t num, size_t sz)
{
    sz *= num;
    auto p = snort_alloc(sz);
    memset(p, 0, sz);
    return p;
}

inline void* snort_calloc(size_t sz)
{ return snort_calloc(1, sz); }

inline void snort_free(void* p)
{ delete[] (uint8_t*)p; }

inline pid_t gettid()
{
#if defined(__linux__) && defined(SYS_gettid)
    return syscall(SYS_gettid);
#else
    return getpid();
#endif
}

SO_PUBLIC const char* get_error(int errnum);

#endif

