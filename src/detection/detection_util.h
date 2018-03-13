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

#ifndef DETECTION_UTIL_H
#define DETECTION_UTIL_H

// this is a legacy junk-drawer file that needs to be refactored
// it provides file and alt data and event trace foo.

#include "main/snort_config.h"

#define DECODE_BLEN 65535

struct DataPointer
{
    const uint8_t* data;
    unsigned len;
};

struct DataBuffer
{
    uint8_t data[DECODE_BLEN];
    unsigned len;
};

// FIXIT-L event trace should be placed in its own files
void EventTrace_Init();
void EventTrace_Term();

void EventTrace_Log(const snort::Packet*, const OptTreeNode*, int action);

inline int EventTrace_IsEnabled()
{
    return ( snort::SnortConfig::get_conf()->event_trace_max > 0 );
}

#endif

