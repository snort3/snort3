//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef SNORT_DEBUG_H
#define SNORT_DEBUG_H

// this provides a module trace capabilty that can be set by config to
// turn on the output of specific debug messages.
//

#include <cstdarg>

#include "main/snort_types.h"

typedef uint64_t Trace;

bool trace_enabled(Trace mask);
bool trace_enabled(Trace mask, Trace flags);

#define TRACE_NAME(name) name##_trace

#ifdef DEBUG_MSGS

void trace_vprintf(const char* name, Trace mask, const char* file, int line,
    Trace flags, const char* fmt, va_list);

template <void (trace_vprintf)(const char*, Trace, const char*, int, Trace, const char*, va_list)>
static inline void trace_printf(const char* name, Trace mask, const char* file, int line,
    Trace flags, const char* fmt, ...) __attribute__((format (printf, 6, 7)));

template <void (trace_vprintf)(const char*, Trace, const char*, int, Trace, const char*, va_list) = trace_vprintf>
static inline void trace_printf(const char* name, Trace mask, const char* file, int line,
    Trace flags, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    trace_vprintf(name, mask, file, line, flags, fmt, ap);

    va_end(ap);
}

template <void (trace_vprintf)(const char*, Trace, const char*, int, Trace, const char*, va_list)>
static inline void trace_printf(const char* name, Trace mask, const char* file,
    int line, const char* fmt, ...) __attribute__((format (printf, 5, 6)));

template <void (trace_vprintf)(const char*, Trace, const char*, int, Trace, const char*, va_list) = trace_vprintf>
static inline void trace_printf(const char* name, Trace mask, const char* file,
    int line, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    trace_vprintf(name, mask, file, line, UINT64_MAX, fmt, ap);

    va_end(ap);
}

template <void (trace_vprintf)(const char*, Trace, const char*, int, Trace, const char*, va_list) = trace_vprintf>
static inline void trace_print(const char* name, Trace mask, const char* file,
    int line, const char* msg)
{
    trace_printf<trace_vprintf>(name, mask, file, line, UINT64_MAX, "%s", msg);
}

template <void (trace_vprintf)(const char*, Trace, const char*, int, Trace, const char*, va_list) = trace_vprintf>
static inline void trace_print(const char* name, Trace mask, const char* file,
    int line, Trace flags, const char* msg)
{
    trace_printf<trace_vprintf>(name, mask, file, line, flags, "%s", msg);
}

#define trace_print trace_print<trace_vprintf>
#define trace_printf trace_printf<trace_vprintf>

#define trace_log(tracer, ...) \
    trace_print(#tracer, tracer##_trace, nullptr, 0, __VA_ARGS__)

#define trace_log_wo_name(tracer, ...) \
    trace_print(nullptr, tracer##_trace, nullptr, 0, __VA_ARGS__)

#define trace_logf(tracer, ...) \
    trace_printf(#tracer, tracer##_trace, nullptr, 0, __VA_ARGS__)

#define trace_logf_wo_name(tracer, ...) \
    trace_printf(nullptr, tracer##_trace, nullptr, 0, __VA_ARGS__)

#define trace_debug(tracer, ...) \
    trace_print(#tracer, tracer##_trace, __FILE__, __LINE__, __VA_ARGS__)

#define trace_debugf(tracer, ...) \
    trace_printf(#tracer, tracer##_trace, __FILE__, __LINE__, __VA_ARGS__)

#else
#define trace_log(tracer, ...)
#define trace_log_wo_name(tracer, ...)
#define trace_logf(tracer, ...)
#define trace_logf_wo_name(tracer, ...)
#define trace_debug(tracer, ...)
#define trace_debugf(tracer, ...)

#endif

#endif

