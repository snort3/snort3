//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// iec104_trace.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after detect_trace.cc (author Maya Dagon <mdagon@cisco.com>)

#ifndef IEC104_TRACE_H
#define IEC104_TRACE_H

// Detection trace utility

#include "main/snort_types.h"

namespace snort
{
struct Packet;
class Trace;
}

extern THREAD_LOCAL const snort::Trace* iec104_trace;

enum
{
    TRACE_IEC104_IDENTIFICATION = 0,
};

#ifdef DEBUG_MSGS
#define print_debug_information(p, msg) debug_log(iec104_trace, TRACE_IEC104_IDENTIFICATION, p, msg)
#else
#define print_debug_information(...)
#endif

#endif

