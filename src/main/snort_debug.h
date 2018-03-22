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

// this provides a set of flags that can be set by environment variable to
// turn on the output of specific debug messages.
//
// FIXIT-M debug flags needs to be replaced with a module facility.

#include <cstdarg>

#include "main/snort_types.h"

// this env var uses the lower 32 bits of the flags:
#define DEBUG_BUILTIN "SNORT_DEBUG"

#define DEBUG_INIT            0x0000000000000001LL
#define DEBUG_PARSER          0x0000000000000002LL
#define DEBUG_PORTLISTS       0x0000000000000004LL
#define DEBUG_ATTRIBUTE       0x0000000000000008LL
#define DEBUG_DECODE          0x0000000000000010LL
#define DEBUG_CONFIGRULES     0x0000000000000020LL
#define DEBUG_DETECT          0x0000000000000040LL
#define DEBUG_PATTERN_MATCH   0x0000000000000080LL
#define DEBUG_FLOW            0x0000000000000100LL
#define DEBUG_LOG             0x0000000000000200LL
#define DEBUG_FLOWBITS        0x0000000000000400LL
#define DEBUG_FILE            0x0000000000000800LL
#define DEBUG_MEMORY          0x0000000000001000LL
// FIXIT-L latency doesn't use any debug messages
#define DEBUG_LATENCY         0x0000000000002000LL
#define DEBUG_SIDE_CHANNEL    0x0000000000004000LL
#define DEBUG_CONNECTORS      0x0000000000008000LL
#define DEBUG_HA              0x0000000000010000LL
#define DEBUG_ANALYZER        0x0000000000020000LL

// this env var uses the upper 32 bits of the flags:
#define DEBUG_PLUGIN "SNORT_PP_DEBUG"

#define DEBUG_FRAG            0x0000000100000000LL
#define DEBUG_STREAM          0x0000000200000000LL
#define DEBUG_STREAM_STATE    0x0000000400000000LL
#define DEBUG_STREAM_PAF      0x0000000800000000LL
#define DEBUG_ASN1            0x0000002000000000LL
#define DEBUG_DNS             0x0000004000000000LL
#define DEBUG_FTPTELNET       0x0000008000000000LL
#define DEBUG_GTP             0x0000010000000000LL
#define DEBUG_SIP             0x0000100000000000LL
#define DEBUG_SMTP            0x0000400000000000LL
#define DEBUG_REPUTATION      0x0000800000000000LL

#define DEBUG_CODEC           0x0001000000000000LL
#define DEBUG_INSPECTOR       0x0002000000000000LL
#define DEBUG_IPS_ACTION      0x0004000000000000LL
#define DEBUG_IPS_OPTION      0x0008000000000000LL
#define DEBUG_MPSE            0x0010000000000000LL
#define DEBUG_SO_RULE         0x0020000000000000LL
#define DEBUG_LOGGER          0x0040000000000000LL
#define DEBUG_APPID           0x0400000000000000LL

#ifdef PIGLET
#define DEBUG_PIGLET          0x0800000000000000LL
#endif

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

class SO_PUBLIC Debug
{
public:
    static bool enabled(uint64_t flag);

    static void print(const char* file, int line, uint64_t dbg, const char* fmt,
        ...) __attribute__((format (printf, 4, 5)));

private:
    static bool init;
    static uint64_t mask;
};

#define DebugFormat(dbg, fmt, ...) \
    Debug::print(__FILE__, __LINE__, dbg, fmt, __VA_ARGS__)

#define DebugFormatNoFileLine(dbg, fmt, ...) \
    Debug::print(nullptr, 0, dbg, fmt, __VA_ARGS__)

#define DebugMessage(dbg, msg) DebugFormat(dbg, "%s", msg)

#define DEBUG_WRAP(code) code

#else
#define trace_log(tracer, ...)
#define trace_log_wo_name(tracer, ...)
#define trace_logf(tracer, ...)
#define trace_logf_wo_name(tracer, ...)
#define trace_debug(tracer, ...)
#define trace_debugf(tracer, ...)

#define DebugFormat(dbg, fmt, ...)
#define DebugFormatNoFileLine(dbg, fmt, ...)
#define DebugMessage(dbg, msg)
#define DEBUG_WRAP(code)
#endif

#endif

