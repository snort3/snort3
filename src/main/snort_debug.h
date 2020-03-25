//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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

// this provides a module trace capability that can be set by config to
// turn on the output of specific debug messages.
//

#include <cstdarg>

#include "main/snort_types.h"
#include "main/trace.h"

namespace snort
{
SO_PUBLIC void trace_vprintf(const char* name, TraceLevel log_level,
    const char* trace_option, const char* fmt, va_list);
}

using trace_func = void(const char*, TraceLevel, const char*, const char*, va_list);

template <trace_func>
static inline void trace_printf(TraceLevel log_level, const snort::Trace& trace,
    TraceOption trace_option, const char* fmt, ...) __attribute__((format (printf, 4, 5)));

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_printf(TraceLevel log_level, const snort::Trace& trace,
    TraceOption trace_option, const char* fmt, ...)
{
    if ( !trace.enabled(trace_option, log_level) )
        return;

    va_list ap;
    va_start(ap, fmt);

    const char* trace_option_name = trace.option_name(trace_option);
    trace_vprintf(trace.module_name(), log_level, trace_option_name, fmt, ap);

    va_end(ap);
}

template <trace_func>
static inline void trace_printf(TraceLevel log_level, const snort::Trace& trace,
    const char* fmt, ...) __attribute__((format (printf, 3, 4)));

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_printf(TraceLevel log_level, const snort::Trace& trace,
    const char* fmt, ...)
{
    if ( !trace.enabled(DEFAULT_TRACE_OPTION, log_level) )
        return;

    va_list ap;
    va_start(ap, fmt);

    const char* trace_option_name = trace.option_name(DEFAULT_TRACE_OPTION);
    trace_vprintf(trace.module_name(), log_level, trace_option_name, fmt, ap);

    va_end(ap);
}

template <trace_func>
static inline void trace_printf(const snort::Trace& trace,
    TraceOption trace_option, const char* fmt, ...) __attribute__((format (printf, 3, 4)));

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_printf(const snort::Trace& trace,
    TraceOption trace_option, const char* fmt, ...)
{
    if ( !trace.enabled(trace_option) )
        return;

    va_list ap;
    va_start(ap, fmt);

    const char* trace_option_name = trace.option_name(trace_option);
    trace_vprintf(trace.module_name(), DEFAULT_LOG_LEVEL, trace_option_name, fmt, ap);

    va_end(ap);
}

template <trace_func>
static inline void trace_printf(const snort::Trace& trace,
    const char* fmt, ...) __attribute__((format (printf, 2, 3)));

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_printf(const snort::Trace& trace, const char* fmt, ...)
{
    if ( !trace.enabled(DEFAULT_TRACE_OPTION) )
        return;

    va_list ap;
    va_start(ap, fmt);

    const char* trace_option_name = trace.option_name(DEFAULT_TRACE_OPTION);
    trace_vprintf(trace.module_name(), DEFAULT_LOG_LEVEL, trace_option_name, fmt, ap);

    va_end(ap);
}

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_print(TraceLevel log_level, const snort::Trace& trace,
    TraceOption trace_option, const char* msg)
{
    trace_printf<trace_vprintf>(log_level, trace, trace_option, "%s", msg);
}

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_print(const snort::Trace& trace, TraceOption trace_option, const char* msg)
{
    trace_printf<trace_vprintf>(trace, trace_option, "%s", msg);
}

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_print(TraceLevel log_level, const snort::Trace& trace,
    const char* msg)
{
    trace_printf<trace_vprintf>(log_level, trace, "%s", msg);
}

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_print(const snort::Trace& trace, const char* msg)
{
    trace_printf<trace_vprintf>(trace, "%s", msg);
}

#define trace_print trace_print<snort::trace_vprintf>
#define trace_printf trace_printf<snort::trace_vprintf>

#define trace_log(...) trace_print(__VA_ARGS__)
#define trace_logf(...) trace_printf(__VA_ARGS__)

#ifdef DEBUG_MSGS
#define debug_log trace_log
#define debug_logf trace_logf
#else
#define debug_log(...)
#define debug_logf(...)
#endif

#endif
