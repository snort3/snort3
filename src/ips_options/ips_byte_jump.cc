//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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
#include "hash/hash_key_operations.h"
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
    uint32_t a = config.bytes_to_grab;
    uint32_t b = config.offset;
    uint32_t c = config.base;

    mix(a,b,c);

    a += (config.relative_flag << 24 |
        config.data_string_convert_flag << 16 |
        config.from_beginning_flag << 8 |
        config.align_flag);
    b += config.endianness;
    c += config.multiplier;

    mix(a,b,c);

    a += config.post_offset;
    b += config.from_end_flag << 16 | (uint32_t) config.offset_var << 8 | config.post_offset_var;
    c += config.bitmask_val;

    mix(a,b,c);
    a += IpsOption::hash();

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
    RuleProfile profile(byteJumpPerfStats);

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
        pos = 0;

    else if ( bjd->from_end_flag )
        pos = c.size();

    else
        pos = (base_ptr - start_ptr) + payload_bytes_grabbed;

    pos += jump + post_offset;

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
    ByteJumpModule() : Module(s_name, s_help, s_params) { data.multiplier = 1; }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &byteJumpPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    ByteJumpData data = {};
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
        data.bytes_to_grab = v.get_uint8();

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
        data.multiplier = v.get_uint16();

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
        data.bitmask_val = v.get_uint32();

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

#ifdef UNIT_TEST
#include <iostream>
#include <climits>

#include "framework/value.h"
#include "framework/parameter.h"

#include "catch/snort_catch.h"

#define NO_MATCH snort::IpsOption::EvalStatus::NO_MATCH
#define MATCH snort::IpsOption::EvalStatus::MATCH

void SetByteJumpData(ByteJumpData &byte_jump, int value)
{
    byte_jump.bytes_to_grab = value; 
    byte_jump.offset = value;
    byte_jump.relative_flag = value; 
    byte_jump.data_string_convert_flag = value; 
    byte_jump.from_beginning_flag = value;
    byte_jump.align_flag = value; 
    byte_jump.endianness = value;
    byte_jump.base = value; 
    byte_jump.multiplier = value;
    byte_jump.post_offset = value;
    byte_jump.bitmask_val = value;
    byte_jump.offset_var = value; 
    byte_jump.from_end_flag = value; 
    byte_jump.post_offset_var = value; 
};

void SetByteJumpMaxValue(ByteJumpData &byte_jump)
{
    byte_jump.bytes_to_grab = UINT_MAX; 
    byte_jump.offset = INT_MAX;
    byte_jump.relative_flag = UCHAR_MAX; 
    byte_jump.data_string_convert_flag = UCHAR_MAX; 
    byte_jump.from_beginning_flag = UCHAR_MAX;
    byte_jump.align_flag = UCHAR_MAX; 
    byte_jump.endianness = UCHAR_MAX;
    byte_jump.base = UINT_MAX; 
    byte_jump.multiplier = UINT_MAX;
    byte_jump.post_offset = INT_MAX;
    byte_jump.bitmask_val = UINT_MAX;
    byte_jump.offset_var = SCHAR_MAX; 
    byte_jump.from_end_flag = UCHAR_MAX; 
    byte_jump.post_offset_var = SCHAR_MAX; 
};

class StubIpsOption : public IpsOption
{
public:
    StubIpsOption(const char* name, option_type_t option_type) : 
        IpsOption(name, option_type) 
    { };

};

class StubEndianness : public Endianness
{
public:
    StubEndianness() = default;
    virtual bool get_offset_endianness(int32_t offset, uint8_t& endian) override
    { return false; } 
};


TEST_CASE("ByteJumpOption test", "[ips_byte_jump]")
{
    ByteJumpData byte_jump;
    SetByteJumpData(byte_jump, 1);
    snort::IpsOption::set_buffer("hello_world");

    SECTION("method hash")
    {
        ByteJumpOption hash_test(byte_jump);
        ByteJumpOption hash_test_equal(byte_jump);
        
        SECTION("Testing hash with very low values")
        {
            SECTION("Hash has same source")
            {
                REQUIRE((hash_test.hash() == hash_test.hash()) == true);
                REQUIRE((hash_test.hash() == hash_test_equal.hash()) == true);

            }

            SECTION("Compare hash from different source")
            {
                SetByteJumpData(byte_jump, 4);
                ByteJumpOption hash_test_diff(byte_jump);
                CHECK((hash_test.hash() == hash_test_diff.hash()) == false); 
            }
        }

        SECTION("Testing hash with maximum values")
        {
            SetByteJumpMaxValue(byte_jump);
            ByteJumpOption hash_test_max(byte_jump);
            ByteJumpOption hash_test_equal_max(byte_jump);

            SECTION("Hash has same source")
            {
                CHECK((hash_test_max.hash() == hash_test_max.hash()) == true);
                CHECK((hash_test_max.hash() == hash_test_equal_max.hash()) == true);
            }

            SECTION("Compare hash from different source")
            {
                SetByteJumpMaxValue(byte_jump);
                ByteJumpOption hash_test_max(byte_jump);
                CHECK((hash_test.hash() == hash_test_max.hash()) == false); 
            }
        }
    }

    SECTION("operator ==")
    {
        ByteJumpOption jump(byte_jump);

        SECTION("Compare IpsOptions with different names")
        {       
            StubIpsOption case_diff_name("not_hello_world", 
                option_type_t::RULE_OPTION_TYPE_BUFFER_USE);
            REQUIRE((jump==case_diff_name) == false);        
        }
  
        SECTION("Compare IpsOptions with different buffer")
        {
            StubIpsOption case_diff_option("hello_world", 
                option_type_t::RULE_OPTION_TYPE_CONTENT);
            REQUIRE((jump==case_diff_option) == false);        
        }
        SECTION("Compare IpsOptions with buffet n/a")
        {
            StubIpsOption case_option_na("hello_world", 
                option_type_t::RULE_OPTION_TYPE_OTHER); 
            REQUIRE((jump==case_option_na) == false);        
        }

        ByteJumpData byte_jump2;
        SetByteJumpData(byte_jump2, 1); 

        SECTION("Compare between equals instans")
        {
            ByteJumpOption jump_1(byte_jump);    
            REQUIRE((jump==jump_1) == true);
        }
        
        SECTION("bytes_to_grab is different")
        {
            byte_jump2.bytes_to_grab = 2;
            ByteJumpOption jump_2_1(byte_jump2);
            REQUIRE((jump==jump_2_1) == false);
            byte_jump2.bytes_to_grab = 1;
        }

        SECTION("offset is different")
        {
            byte_jump2.offset = 2;
            ByteJumpOption jump_2_2(byte_jump2);
            REQUIRE((jump==jump_2_2) == false);
            byte_jump2.offset = 1;
        }

        SECTION("relative_flag is different")
        {
            byte_jump2.relative_flag = 0;
            ByteJumpOption jump_2_3(byte_jump2);
            REQUIRE((jump==jump_2_3) == false);
            byte_jump2.relative_flag = 1;
        }

        SECTION("data_string_convert_flag is different")
        {
            byte_jump2.data_string_convert_flag = 0;
            ByteJumpOption jump_2_4(byte_jump2);
            REQUIRE((jump==jump_2_4) == false);
            byte_jump2.data_string_convert_flag = 1;
        }
        
        SECTION("from_beginning_flag is different")
        {
            byte_jump2.from_beginning_flag = 0;
            ByteJumpOption jump_2_5(byte_jump2);
            REQUIRE((jump==jump_2_5) == false);
            byte_jump2.from_beginning_flag = 1;
        }

        SECTION("align_flag is different")
        {
            byte_jump2.align_flag = 0;
            ByteJumpOption jump_2_6(byte_jump2);
            REQUIRE((jump==jump_2_6) == false);
            byte_jump2.align_flag = 1;
        }

        SECTION("endianness is different")
        {
            byte_jump2.endianness = 0;
            ByteJumpOption jump_2_7(byte_jump2);
            REQUIRE((jump==jump_2_7) == false);
            byte_jump2.endianness = 1;
        }

        SECTION("base is different")
        {
            byte_jump2.base = 2;
            ByteJumpOption jump_2_8(byte_jump2);
            REQUIRE((jump==jump_2_8) == false);
            byte_jump2.base = 1;
        }

        SECTION("multiplier is different")
        {
            byte_jump2.multiplier = 2;
            ByteJumpOption jump_2_9(byte_jump2);
            REQUIRE((jump==jump_2_9) == false);
            byte_jump2.multiplier = 1;
        }

        SECTION("post_offset is different")
        {
            byte_jump2.post_offset = 2;
            ByteJumpOption jump_2_10(byte_jump2);
            REQUIRE((jump==jump_2_10) == false);
            byte_jump2.post_offset = 1;
        }

        SECTION("bitmask_val is different")
        {
            byte_jump2.bitmask_val = 2;
            ByteJumpOption jump_2_11(byte_jump2);
            REQUIRE((jump==jump_2_11) == false);
            byte_jump2.bitmask_val = 0;
        }

        SECTION("offset_var is different")
        {
            byte_jump2.offset_var = 0;
            ByteJumpOption jump_2_12(byte_jump2);
            REQUIRE((jump==jump_2_12) == false);
            byte_jump2.offset_var = 1;
        }

        SECTION("from_end_flag is different")
        {
            byte_jump2.from_end_flag = 0;
            ByteJumpOption jump_2_13(byte_jump2);
            REQUIRE((jump==jump_2_13) == false);
            byte_jump2.from_end_flag = 1;
        }

        SECTION("post_offset_var is different")
        {
            byte_jump2.post_offset_var = 0;
            ByteJumpOption jump_2_14(byte_jump2);
            REQUIRE((jump==jump_2_14) == false);
            byte_jump2.post_offset_var = 1;
        }
      
    }

    SECTION("method eval")
    {
        Packet test_packet;
        Cursor current_cursor;
        SetByteJumpData(byte_jump, 1);
        
        SECTION("Incorrect Endianness")
        {
            StubEndianness* stub_endinness = new StubEndianness();
            byte_jump.offset_var = -1;
            test_packet.endianness = stub_endinness; 
            byte_jump.endianness = 4;
            byte_jump.post_offset_var = -1;
            ByteJumpOption test_1(byte_jump);
            REQUIRE((test_1.eval(current_cursor, &test_packet)) == NO_MATCH);
        }

        SECTION("Cursor not setted correct for string_extract")
        {
            ByteJumpOption test_2(byte_jump);
            REQUIRE((test_2.eval(current_cursor, &test_packet)) == NO_MATCH);
        }

        SECTION("Extract too much (1000000) bytes from in byte_extract")
        {
            uint8_t buff = 0; 
            byte_jump.data_string_convert_flag = 0;
            byte_jump.bytes_to_grab = 1000000;
            current_cursor.set("hello_world_long_name", &buff, 50);
            ByteJumpOption test_3(byte_jump);
            REQUIRE((test_3.eval(current_cursor, &test_packet)) == NO_MATCH);
        }
        
        SECTION("Cursor not setted correct")
        {
            uint8_t buff = 0; 
            current_cursor.set("hello_world_long_name", &buff, 1);
            byte_jump.data_string_convert_flag = 0;
            byte_jump.from_beginning_flag = 0;
            byte_jump.from_end_flag = 1; 
            byte_jump.bytes_to_grab = 1;
            byte_jump.post_offset_var = 12;
            ByteJumpOption test_4(byte_jump);
            REQUIRE((test_4.eval(current_cursor, &test_packet)) == NO_MATCH);
        }

        SECTION("Match")
        {
            uint8_t buff = 0; 
            byte_jump.data_string_convert_flag = 0;
            byte_jump.from_beginning_flag = 0;
            byte_jump.from_end_flag = 0; 
            current_cursor.set("hello_world_long_name", &buff, 50);
            ByteJumpOption test_5(byte_jump);
            REQUIRE((test_5.eval(current_cursor, &test_packet)) == MATCH);

            byte_jump.from_beginning_flag = 1; 
            byte_jump.bitmask_val = 2;
            ByteJumpOption test_5_1(byte_jump);
            REQUIRE((test_5_1.eval(current_cursor, &test_packet)) == MATCH);
        }
    }
}

TEST_CASE("ByteJumpModule test", "[ips_byte_jump]")
{
    ByteJumpModule module_jump;
    ByteJumpData byte_jump;
    SetByteJumpData(byte_jump, 1);

    SECTION("method end")
    {
        std::string buff = "tmp";

        SECTION("Undefined rule option for var")
        {
            module_jump.var = buff;
            byte_jump.offset_var = -1;
            module_jump.data = byte_jump;
            REQUIRE(module_jump.end("tmp", 0, nullptr) == false);
        }

        SECTION("Undefined rule option for offset_var")
        {
            module_jump.var.clear();
            module_jump.post_var = buff;
            byte_jump.post_offset_var = -1;
            module_jump.data = byte_jump;
            REQUIRE(module_jump.end("tmp", 0, nullptr) == false);        
        }
        
        SECTION("From_beginning and from_end options together")        
        {
            byte_jump.endianness = 0;
            module_jump.data = byte_jump;
            REQUIRE(module_jump.end("tmp", 0, nullptr) == false);  
        }

        SECTION("Number of bytes in \"bitmask\" value is greater than bytes to extract")
        {
            byte_jump.from_beginning_flag = 0;
            byte_jump.bytes_to_grab = 0;
            module_jump.data = byte_jump;
            REQUIRE(module_jump.end("tmp", 0, nullptr) == false);
        }

        SECTION("byte_jump rule option cannot extract more than %d bytes without valid string prefix")
        {
            byte_jump.from_beginning_flag = 0;
            byte_jump.bytes_to_grab = 5;
            byte_jump.data_string_convert_flag = 0;
            module_jump.data = byte_jump;
            REQUIRE(module_jump.end("tmp", 0, nullptr) == false);
        }
        
        SECTION("Case with returned value true")
        {
            byte_jump.from_beginning_flag = 0;
            module_jump.data = byte_jump;
            REQUIRE(module_jump.end("tmp", 0, nullptr) == true);
        }
    }

    SECTION("method set")
    {
        Value value(false);

        SECTION("All params incorrect")
        {
            REQUIRE(module_jump.set(nullptr, value, nullptr) == false);
        }

        SECTION("Case param \"~count\"")
        {
            Parameter param("~count", snort::Parameter::Type::PT_BOOL, 
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        }

        SECTION("Case param \"~offset\"") 
        {
            SECTION("Value doesn't have a str")
            {
                Parameter param("~offset", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help");
                value.set(&param);
                REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
            }
            
            SECTION("When value has a str")
            {
                Value value_tmp("123");
                Parameter param("~offset", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help");
                value_tmp.set(&param);
                REQUIRE(module_jump.set(nullptr, value_tmp, nullptr) == true);
            }
        }

        SECTION("Case param \"relative\"") 
        { 
            Parameter param("relative", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        }

        SECTION("Param \"from_beginning\" correct")
        {
            Parameter param("from_beginning", snort::Parameter::Type::PT_BOOL, 
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        }

        SECTION("Case param \"from_end\"") 
        { 
            Parameter param("from_end", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        } 

        SECTION("Case param \"align\"") 
        { 
            Parameter param("align", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        } 
        
        SECTION("Case param \"multiplier\"") 
        { 
            Parameter param("multiplier", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        } 

        SECTION("Case param \"post_offset\"") 
        {
            SECTION("Value doesn't have a str")
            {
                Parameter param("post_offset", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help");
                value.set(&param);
                REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
            }
            
            SECTION("When value has a str")
            {
                Value value_tmp("123");
                Parameter param("post_offset", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help");
                value_tmp.set(&param);
                REQUIRE(module_jump.set(nullptr, value_tmp, nullptr) == true);
            }
        }

        SECTION("Case param \"big\"") 
        { 
            Parameter param("big", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        }  

        SECTION("Case param \"little\"") 
        { 
            Parameter param("little", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        }

        SECTION("Case param \"dce\"") 
        { 
            Parameter param("dce", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        }

        SECTION("Case param \"string\"") 
        { 
            Parameter param("string", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        }

        SECTION("Case param \"dec\"") 
        { 
            Parameter param("dec", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        }

        SECTION("Case param \"hex\"") 
        { 
            Parameter param("hex", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        } 

        SECTION("Case param \"oct\"") 
        { 
            Parameter param("oct", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        } 

        SECTION("Case param \"bitmask\"") 
        { 
            Parameter param("bitmask", snort::Parameter::Type::PT_BOOL, 
                    nullptr, "default", "help"); 
            value.set(&param);
            REQUIRE(module_jump.set(nullptr, value, nullptr) == true);
        } 
    }
}

#endif