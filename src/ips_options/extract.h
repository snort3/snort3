//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef EXTRACT_H
#define EXTRACT_H

#include "framework/cursor.h"
#include "framework/endianness.h"
#include "main/snort_types.h"
#include "main/thread.h"
#include "protocols/packet.h"

#define ENDIAN_BIG    0x1
#define ENDIAN_LITTLE 0x2
#define ENDIAN_FUNC   0x4

#define PARSELEN      10
#define MAX_BYTES_TO_GRAB 4

#define NUM_IPS_OPTIONS_VARS 2
#define IPS_OPTIONS_NO_VAR (-1)
#define INVALID_VAR_ERR_STR "%s uses an undefined rule option variable (%s)"

namespace snort
{

struct ByteData
{
    uint32_t base;
    uint32_t bitmask_val;
    uint32_t bytes_to_extract;
    int32_t offset;
    uint8_t endianness;
    bool relative_flag;
    bool string_convert_flag;
};

SO_PUBLIC int string_extract(
    int bytes_to_grab, int base, const uint8_t* ptr,
    const uint8_t* start, const uint8_t* end, uint32_t* value);

SO_PUBLIC int byte_extract(
    int endianness, int bytes_to_grab, const uint8_t* ptr,
    const uint8_t* start, const uint8_t* end, uint32_t* value);

void set_cursor_bounds(const ByteData& settings, const Cursor& c,
    const uint8_t*& start, const uint8_t*& ptr, const uint8_t*& end);

int32_t data_extraction(const ByteData& settings, Packet* p,
    uint32_t& result_var, const uint8_t* start,
    const uint8_t* ptr, const uint8_t* end);

int32_t extract_data(const ByteData& settings, const Cursor& c, Packet* p,
    uint32_t& result_var);

SO_PUBLIC void set_byte_order(uint8_t& order, uint8_t flag, const char* opt);

SO_PUBLIC uint32_t getNumberTailingZerosInBitmask(uint32_t);
SO_PUBLIC uint8_t numBytesInBitmask(uint32_t);

// Used during parsing
SO_PUBLIC int8_t GetVarByName(const char* name);
SO_PUBLIC int8_t AddVarNameToList(const char* name);
// Called at the end of rule parsing
SO_PUBLIC void ClearIpsOptionsVars();
// Used during eval
SO_PUBLIC int GetVarValueByIndex(uint32_t* dst, uint8_t var_number);
SO_PUBLIC int SetVarValueByIndex(uint32_t value, uint8_t var_number);
}
#endif
