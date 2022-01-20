//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "protocols/packet.h"
#include "trace/trace.h"
#include "trace/trace_api.h"

static inline bool trace_enabled(const snort::Trace* trace,
    TraceOptionID trace_option_id,
    TraceLevel log_level = DEFAULT_TRACE_LOG_LEVEL,
    const snort::Packet* p = nullptr)
{
    if ( !trace or !trace->enabled(trace_option_id, log_level) )
        return false;

    if ( !p )
        return true;

    const auto gid = snort::TraceApi::get_constraints_generation();
    if ( !p->filtering_state.was_checked(gid) )
        snort::TraceApi::filter(*p);

    return p->filtering_state.matched;
}

namespace snort
{
SO_PUBLIC void trace_vprintf(const char* name, TraceLevel log_level,
    const char* trace_option, const snort::Packet* p, const char* fmt, va_list);
}

using trace_func = void(const char*, TraceLevel, const char*, const snort::Packet*, const char*, va_list);

template <trace_func>
static inline void trace_uprintf(const snort::Trace* trace,
    TraceOptionID trace_option_id, const snort::Packet* p, const char* fmt, ...) __attribute__((format (printf, 4, 5)));

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_uprintf(const snort::Trace* trace,
    TraceOptionID trace_option_id, const snort::Packet* p, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    const char* trace_option_name = trace->option_name(trace_option_id);
    trace_vprintf(trace->module_name(), DEFAULT_TRACE_LOG_LEVEL, trace_option_name, p, fmt, ap);

    va_end(ap);
}

template <trace_func>
static inline void trace_printf(TraceLevel log_level,
    const snort::Trace* trace, TraceOptionID trace_option_id,
    const snort::Packet* p, const char* fmt, ...)
    __attribute__((format (printf, 5, 6)));

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_printf(TraceLevel log_level,
    const snort::Trace* trace, TraceOptionID trace_option_id,
    const snort::Packet* p, const char* fmt, ...)
{
    if ( !trace_enabled(trace, trace_option_id, log_level, p) )
        return;

    va_list ap;
    va_start(ap, fmt);

    const char* trace_option_name = trace->option_name(trace_option_id);
    trace_vprintf(trace->module_name(), log_level, trace_option_name, p,
        fmt, ap);

    va_end(ap);
}

template <trace_func>
static inline void trace_printf(TraceLevel log_level,
    const snort::Trace* trace, const snort::Packet* p,
    const char* fmt, ...) __attribute__((format (printf, 4, 5)));

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_printf(TraceLevel log_level,
    const snort::Trace* trace, const snort::Packet* p,
    const char* fmt, ...)
{
    if ( !trace_enabled(trace, DEFAULT_TRACE_OPTION_ID, log_level, p) )
        return;

    va_list ap;
    va_start(ap, fmt);

    const char* trace_option_name = trace->option_name(DEFAULT_TRACE_OPTION_ID);
    trace_vprintf(trace->module_name(), log_level, trace_option_name, p,
        fmt, ap);

    va_end(ap);
}

template <trace_func>
static inline void trace_printf(const snort::Trace* trace,
    TraceOptionID trace_option_id, const snort::Packet* p,
    const char* fmt, ...) __attribute__((format (printf, 4, 5)));

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_printf(const snort::Trace* trace,
    TraceOptionID trace_option_id, const snort::Packet* p, const char* fmt, ...)
{
    if ( !trace_enabled(trace, trace_option_id, DEFAULT_TRACE_LOG_LEVEL, p) )
        return;

    va_list ap;
    va_start(ap, fmt);

    const char* trace_option_name = trace->option_name(trace_option_id);
    trace_vprintf(trace->module_name(), DEFAULT_TRACE_LOG_LEVEL,
        trace_option_name, p, fmt, ap);

    va_end(ap);
}

template <trace_func>
static inline void trace_printf(const snort::Trace* trace,
    const snort::Packet* p, const char* fmt, ...)
    __attribute__((format (printf, 3, 4)));

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_printf(const snort::Trace* trace,
    const snort::Packet* p, const char* fmt, ...)
{
    if ( !trace_enabled(trace, DEFAULT_TRACE_OPTION_ID, DEFAULT_TRACE_LOG_LEVEL, p) )
        return;

    va_list ap;
    va_start(ap, fmt);

    const char* trace_option_name = trace->option_name(DEFAULT_TRACE_OPTION_ID);
    trace_vprintf(trace->module_name(), DEFAULT_TRACE_LOG_LEVEL,
        trace_option_name, p, fmt, ap);

    va_end(ap);
}

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_print(TraceLevel log_level,
    const snort::Trace* trace, TraceOptionID trace_option_id,
    const snort::Packet* p, const char* msg)
{
    trace_printf<trace_vprintf>(log_level, trace, trace_option_id, p,
        "%s", msg);
}

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_print(const snort::Trace* trace,
    TraceOptionID trace_option_id, const snort::Packet* p, const char* msg)
{
    trace_printf<trace_vprintf>(trace, trace_option_id, p, "%s", msg);
}

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_print(TraceLevel log_level,
    const snort::Trace* trace, const snort::Packet* p, const char* msg)
{
    trace_printf<trace_vprintf>(log_level, trace, p, "%s", msg);
}

template <trace_func trace_vprintf = snort::trace_vprintf>
static inline void trace_print(const snort::Trace* trace, const snort::Packet* p,
    const char* msg)
{
    trace_printf<trace_vprintf>(trace, p, "%s", msg);
}

#define trace_print trace_print<snort::trace_vprintf>
#define trace_printf trace_printf<snort::trace_vprintf>
#define trace_uprintf trace_uprintf<snort::trace_vprintf>

#define trace_log(...) trace_print(__VA_ARGS__)
#define trace_logf(...) trace_printf(__VA_ARGS__)
#define trace_ulogf(...) trace_uprintf(__VA_ARGS__)

#ifdef DEBUG_MSGS
#define debug_log trace_log
#define debug_logf trace_logf
#else
#define debug_log(...)
#define debug_logf(...)
#endif

#endif
