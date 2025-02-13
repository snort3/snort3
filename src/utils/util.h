//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "main/snort_types.h"

// Note: thread names > 15 chars aren't supported on most systems
#if defined(__linux__)
    #include <pthread.h>
    #define SET_THREAD_NAME(thread, name) \
    pthread_setname_np(thread, name)

#elif defined(__OpenBSD__) || defined(__FreeBSD__)
    #include <pthread_np.h>
    #define SET_THREAD_NAME(thread, name) \
    pthread_set_name_np(thread, name)

#else
    #define SET_THREAD_NAME(thread, name) \
    UNUSED(thread);\
    UNUSED(name);

#endif

#define TIMEBUF_SIZE 27

#define SECONDS_PER_DAY  86400  /* number of seconds in a day  */
#define SECONDS_PER_HOUR  3600  /* number of seconds in a hour */
#define SECONDS_PER_MIN     60     /* number of seconds in a minute */

unsigned int get_random_seed();
bool get_file_size(const std::string&, size_t&);
bool is_directory_path(const std::string&);

namespace
{
inline void COPY4(uint32_t* dst, const uint32_t* src)
{
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}
}

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
    return syscall(SYS_gettid); // cppcheck-suppress ConfigurationNotChecked
#else
    return getpid();
#endif
}

namespace snort
{
SO_PUBLIC const char* get_error(int errnum);
SO_PUBLIC char* snort_strdup(const char*);
SO_PUBLIC char* snort_strndup(const char*, size_t);
SO_PUBLIC void ts_print(const struct timeval*, char*, bool yyyymmdd = false);
void uint8_to_printable_str(const uint8_t* buff, unsigned len, std::string& print_str);
SO_PUBLIC void str_to_int_vector(const std::string& s, char delim, std::vector<uint32_t>& elems);
SO_PUBLIC std::string int_vector_to_str(const std::vector<uint32_t>& elems, char delim = ',');
SO_PUBLIC bool rotate_file_for_max_size(const char* file_owner, const char* old_file,
    FILE* old_fh, uint32_t max_file_size);
SO_PUBLIC bool check_file_size(FILE* fh, uint64_t max_file_size);
}

#endif

