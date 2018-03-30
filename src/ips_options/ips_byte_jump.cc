//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

/* sp_byte_jump
 * Author: Martin Roesch
 *
 * Purpose:
 *      Grab some number of bytes, convert them to their numeric
 *      representation, jump the cursor up that many bytes (for
 *      further pattern matching/byte_testing).
 *
 *
 * Arguments:
 *      Required:
 *      <bytes_to_grab>: number of bytes to pick up from the packet
 *      <offset>: number of bytes into the payload to grab the bytes
 *      Optional:
 *      ["relative"]: offset relative to last pattern match
 *      ["multiplier <value>"]: Multiply the number of calculated bytes by
 *                             <value> and skip forward that number of bytes
 *      ["big"]: process data as big endian (default)
 *      ["little"]: process data as little endian
 *      ["dce"]: let the DCE/RPC 2 preprocessor determine the byte order of the
 *               value to be converted
 *      ["string"]: converted bytes represented as a string needing conversion
 *      ["hex"]: converted string data is represented in hexadecimal
 *      ["dec"]: converted string data is represented in decimal
 *      ["oct"]: converted string data is represented in octal
 *      ["align"]: round the number of converted bytes up to the next
 *                 32-bit boundary
 *      ["post_offset"]: number of bytes to adjust after applying
 *      ["from beginning"]: Skip forward from the beginning of the packet
 *                          payload instead of from the current position in
 *                          the packet.
 *      ["from_end"]: the jump will originate from the end of payload
 *      ["bitmask"]: Applies the AND operator on the bytes to convert argument.
 *                   The result will be right-shifted by the number of bits
 *                   equal to the number of trailing zeros in the mask.
 *
 *   sample rules:
 *   alert udp any any -> any 32770:34000 (content: "|00 01 86 B8|"; \
 *       content: "|00 00 00 01|"; distance: 4; within: 4; \
 *       byte_jump: 4, 12, relative, align; \
 *       byte_test: 4, >, 900, 20, relative; \
 *       msg: "statd format string buffer overflow";)
 *
 * Effect:
 *
 *      Reads in the indicated bytes, converts them to an numeric
 *      representation and then jumps the cursor up
 *      that number of bytes.  Returns 1 if the jump is in range (within the
 *      packet) and 0 if it's not.
 *
 * Comments:
 *
 * Any comments?
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/endianness.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "extract.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL ProfileStats byteJumpPerfStats;

#define s_name "byte_jump"

typedef struct _ByteJumpData
{
    uint32_t bytes_to_grab;
    int32_t offset;
    uint8_t relative_flag;
    uint8_t data_string_convert_flag;
    uint8_t from_beginning_flag;
    uint8_t align_flag;
    uint8_t endianness;
    uint32_t base;
    uint32_t multiplier;
    int32_t post_offset;
    uint32_t bitmask_val;
    int8_t offset_var;
    uint8_t from_end_flag;
    int8_t post_offset_var;
} ByteJumpData;

class ByteJumpOption : public IpsOption
{
public:
    ByteJumpOption(const ByteJumpData& c) : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE)
    { config = c; }


    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return (config.relative_flag == 1); }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    ByteJumpData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteJumpOption::hash() const
{
    uint32_t a,b,c;
    const ByteJumpData* data = &config;

    a = data->bytes_to_grab;
    b = data->offset;
    c = data->base;

    mix(a,b,c);

    a += (data->relative_flag << 24 |
        data->data_string_convert_flag << 16 |
        data->from_beginning_flag << 8 |
        data->align_flag);
    b += data->endianness;
    c += data->multiplier;

    mix(a,b,c);

    a += data->post_offset;
    b += data->from_end_flag << 16 | (uint32_t) data->offset_var << 8 | data->post_offset_var;
    c += data->bitmask_val;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    finalize(a,b,c);

    return c;
}

bool ByteJumpOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const ByteJumpOption& rhs = (const ByteJumpOption&)ips;
    const ByteJumpData* left = &config;
    const ByteJumpData* right = &rhs.config;

    if (( left->bytes_to_grab == right->bytes_to_grab) &&
        ( left->offset == right->offset) &&
        ( left->offset_var == right->offset_var) &&
        ( left->relative_flag == right->relative_flag) &&
        ( left->data_string_convert_flag == right->data_string_convert_flag) &&
        ( left->from_beginning_flag == right->from_beginning_flag) &&
        ( left->align_flag == right->align_flag) &&
        ( left->endianness == right->endianness) &&
        ( left->base == right->base) &&
        ( left->multiplier == right->multiplier) &&
        ( left->post_offset == right->post_offset) &&
        ( left->bitmask_val == right->bitmask_val) &&
        ( left->from_end_flag == right->from_end_flag) &&
        ( left->post_offset_var == right->post_offset_var))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus ByteJumpOption::eval(Cursor& c, Packet* p)
{
    Profile profile(byteJumpPerfStats);

    ByteJumpData* bjd = (ByteJumpData*)&config;

    int32_t offset = 0;
    int32_t post_offset = 0;

    // Get values from byte_extract variables, if present.
    if (bjd->offset_var >= 0 && bjd->offset_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t extract_offset;
        GetVarValueByIndex(&extract_offset, bjd->offset_var);
        offset = (int32_t)extract_offset;
    }
    else
    {
        offset = bjd->offset;
    }
    if (bjd->post_offset_var >= 0 && bjd->post_offset_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t extract_post_offset;
        GetVarValueByIndex(&extract_post_offset, bjd->post_offset_var);
        post_offset = (int32_t)extract_post_offset;
    }
    else
    {
        post_offset = bjd->post_offset;
    }

    const uint8_t* const start_ptr = c.buffer();
    const uint8_t* const end_ptr = start_ptr + c.size();
    const uint8_t* const base_ptr = offset +
        ((bjd->relative_flag) ? c.start() : start_ptr);

    uint32_t jump = 0;
    uint32_t payload_bytes_grabbed = 0;
    uint8_t endian = bjd->endianness;

    if (endian == ENDIAN_FUNC)
    {
        if (!p->endianness ||
            !p->endianness->get_offset_endianness(base_ptr - p->data, endian))
            return NO_MATCH;
    }

    // Both of the extraction functions contain checks to ensure the data
    // is inbounds and will return no match if it isn't
    if (bjd->bytes_to_grab)
    {
        if ( !bjd->data_string_convert_flag )
        {
            if ( byte_extract(
                endian, bjd->bytes_to_grab,
                base_ptr, start_ptr, end_ptr, &jump) )
                return NO_MATCH;

            payload_bytes_grabbed = bjd->bytes_to_grab;
        }
        else
        {
            int32_t tmp = string_extract(
                bjd->bytes_to_grab, bjd->base,
                base_ptr, start_ptr, end_ptr, &jump);

            if (tmp < 0)
                return NO_MATCH;

            payload_bytes_grabbed = tmp;
        }

        // Negative offsets that put us outside the buffer should have been caught
        // in the extraction routines
        assert(base_ptr >= c.buffer());

        if (bjd->bitmask_val != 0 )
        {
            uint32_t num_tailing_zeros_bitmask = getNumberTailingZerosInBitmask(bjd->bitmask_val);
            jump = jump & bjd->bitmask_val;
            if (jump && num_tailing_zeros_bitmask )
            {
                jump = jump >> num_tailing_zeros_bitmask;
            }
        }

        if (bjd->multiplier)
            jump *= bjd->multiplier;

        // if we need to align on 32-bit boundaries, round up to the next 32-bit value
        if (bjd->align_flag)
        {
            if ((jump % 4) != 0)
            {
                jump += (4 - (jump % 4));
            }
        }
    }

    uint32_t pos;

    if ( bjd->from_beginning_flag )
        pos = jump;

    else if ( bjd->from_end_flag )
        pos = c.size() + jump;

    else
        pos = c.get_pos() + offset + payload_bytes_grabbed + jump;

    pos += post_offset;

    if ( !c.set_pos(pos) )
        return NO_MATCH;

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~count", Parameter::PT_INT, "0:10", nullptr,
      "number of bytes to pick up from the buffer" },

    { "~offset", Parameter::PT_STRING, nullptr, nullptr,
      "variable name or number of bytes into the buffer to start processing" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "offset from cursor instead of start of buffer" },

    { "from_beginning", Parameter::PT_IMPLIED, nullptr, nullptr,
      "jump from start of buffer instead of cursor" },

    { "from_end", Parameter::PT_IMPLIED, nullptr, nullptr,
      "jump backward from end of buffer" },

    { "multiplier", Parameter::PT_INT, "1:65535", "1",
      "scale extracted value by given amount" },

    { "align", Parameter::PT_INT, "0:4", "0",
      "round the number of converted bytes up to the next 2- or 4-byte boundary" },

    { "post_offset", Parameter::PT_STRING, nullptr, nullptr,
      "skip forward or backward (positive or negative value) by variable name or number of " \
      "bytes after the other jump options have been applied" },

    { "big", Parameter::PT_IMPLIED, nullptr, nullptr,
      "big endian" },

    { "little", Parameter::PT_IMPLIED, nullptr, nullptr,
      "little endian" },

    { "dce", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dcerpc2 determines endianness" },

    { "string", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from string" },

    { "hex", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from hex string" },

    { "oct", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from octal string" },

    { "dec", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from decimal string" },

    { "bitmask", Parameter::PT_INT, "0x1:0xFFFFFFFF", nullptr,
      "applies as an AND prior to evaluation" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to move the detection cursor"

class ByteJumpModule : public Module
{
public:
    ByteJumpModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &byteJumpPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    ByteJumpData data;
    string var;
    string post_var;
};

bool ByteJumpModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    var.clear();
    post_var.clear();
    data.multiplier = 1;
    return true;
}

bool ByteJumpModule::end(const char*, int, SnortConfig*)
{
    if ( var.empty() )
        data.offset_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.offset_var = GetVarByName(var.c_str());

        if (data.offset_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "byte_jump", var.c_str());
            return false;
        }
    }
    if ( post_var.empty() )
        data.post_offset_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.post_offset_var = GetVarByName(post_var.c_str());

        if (data.post_offset_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "byte_jump", post_var.c_str());
            return false;
        }
    }
    if ( !data.endianness )
        data.endianness = ENDIAN_BIG;

    if (data.from_beginning_flag && data.from_end_flag)
    {
        ParseError("from_beginning and from_end options together in a rule\n");
        return false;
    }

    if ( data.bitmask_val && (numBytesInBitmask(data.bitmask_val) > data.bytes_to_grab))
    {
        ParseError("Number of bytes in \"bitmask\" value is greater than bytes to extract.");
        return false;
    }

    if ((data.bytes_to_grab > MAX_BYTES_TO_GRAB) && !data.data_string_convert_flag)
    {
        ParseError(
            "byte_jump rule option cannot extract more than %d bytes without valid string prefix.",
            MAX_BYTES_TO_GRAB);
        return false;
    }

    return true;
}

bool ByteJumpModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~count") )
        data.bytes_to_grab = v.get_long();

    else if ( v.is("~offset") )
    {
        long n;
        if ( v.strtol(n) )
            data.offset = n;
        else
            var = v.get_string();
    }
    else if ( v.is("relative") )
        data.relative_flag = 1;

    else if ( v.is("from_beginning") )
        data.from_beginning_flag = 1;

    else if ( v.is("align") )
        data.align_flag = 1;

    else if ( v.is("multiplier") )
        data.multiplier = v.get_long();

    else if ( v.is("post_offset") )
    {
        long n;
        if ( v.strtol(n) )
            data.post_offset = n;
        else
            post_var = v.get_string();
    }
    else if ( v.is("big") )
        set_byte_order(data.endianness, ENDIAN_BIG, "byte_jump");

    else if ( v.is("little") )
        set_byte_order(data.endianness, ENDIAN_LITTLE, "byte_jump");

    else if ( v.is("dce") )
        set_byte_order(data.endianness, ENDIAN_FUNC, "byte_jump");

    else if ( v.is("string") )
    {
        data.data_string_convert_flag = 1;
        data.base = 10;
    }
    else if ( v.is("dec") )
        data.base = 10;

    else if ( v.is("hex") )
        data.base = 16;

    else if ( v.is("oct") )
        data.base = 8;

    else if ( v.is("from_end") )
        data.from_end_flag = 1;

    else if ( v.is("bitmask") )
        data.bitmask_val = v.get_long();
    
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ByteJumpModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* byte_jump_ctor(Module* p, OptTreeNode*)
{
    ByteJumpModule* m = (ByteJumpModule*)p;
    return new ByteJumpOption(m->data);
}

static void byte_jump_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi byte_jump_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    byte_jump_ctor,
    byte_jump_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_byte_jump[] =
#endif
{
    &byte_jump_api.base,
    nullptr
};

