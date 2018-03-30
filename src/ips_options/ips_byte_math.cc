//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_byte_math.cc authors  Maya Dagon   <mdagon@cisco.com>
//                           Krishnakanth <vkambala@cisco.com>
//                           Seshaiah     <serugu@cisco.com>

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
#include "profiler/profiler.h"
#include "utils/util.h"

#include "extract.h"

using namespace snort;
using namespace std;

#define s_name "byte_math"

#define s_help \
    "rule option to perform mathematical operations on extracted value and a specified \
value or existing variable"

enum BM_Oper // must match the exact order in Parameter table - i.e "+|-|*|/|<<|>>"
{
    BM_PLUS = 0,
    BM_MINUS,
    BM_MULTIPLY,
    BM_DIVIDE,
    BM_LEFT_SHIFT,
    BM_RIGHT_SHIFT
};

static THREAD_LOCAL ProfileStats byteMathPerfStats;

struct ByteMathData
{
    uint32_t bytes_to_extract;
    uint32_t rvalue;
    int32_t offset;
    uint32_t bitmask_val;
    char* result_name;
    BM_Oper oper;
    bool relative_flag;
    bool string_convert_flag;
    uint8_t base;
    uint8_t endianess;
    int8_t result_var;
    int8_t rvalue_var;
    int8_t offset_var;
};

class ByteMathOption : public IpsOption
{
public:
    ByteMathOption(const ByteMathData& c) : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE),
        config(c) { }

    ~ByteMathOption() override
    { snort_free(config.result_name); }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return config.relative_flag; }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    const ByteMathData config;
};

uint32_t ByteMathOption::hash() const
{
    uint32_t a,b,c;
    const ByteMathData* data = &config;

    a = data->bytes_to_extract;
    b = data->rvalue;
    c = data->oper;

    mix(a,b,c);

    a += data->offset;
    b += ((uint32_t) data->rvalue_var << 24 |
        (uint32_t) data->offset_var << 16 |
        (uint32_t) data->result_var << 8 |
        data->endianess);
    c += data->base;

    mix(a,b,c);

    a += data->bitmask_val;
    b += data->relative_flag;
    c += data->string_convert_flag;
    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool ByteMathOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const ByteMathOption& rhs = (const ByteMathOption&)ips;
    const ByteMathData* left = &config;
    const ByteMathData* right = &rhs.config;

    if (( left->bytes_to_extract == right->bytes_to_extract) &&
        ( left->rvalue == right->rvalue) &&
        ( left->oper == right->oper) &&
        ( left->offset == right->offset) &&
        ( left->relative_flag == right->relative_flag) &&
        ( left->string_convert_flag == right->string_convert_flag) &&
        ( left->endianess == right->endianess) &&
        ( left->base == right->base) &&
        ( left->bitmask_val == right->bitmask_val) &&
        ( left->rvalue_var == right->rvalue_var) &&
        ( left->offset_var == right->offset_var) &&
        ( left->result_var == right->result_var))
    {
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

IpsOption::EvalStatus ByteMathOption::eval(Cursor& c, Packet* p)
{
    Profile profile(byteMathPerfStats);

    if (p == nullptr)
        return NO_MATCH;

    const uint8_t* start = c.buffer();
    int dsize = c.size();

    const uint8_t* ptr = config.relative_flag ? c.start() : c.buffer();
    const uint8_t* end = start + dsize;

    /* Get values from ips options variables, if present. */
    uint32_t rvalue;
    if (config.rvalue_var >= 0 && config.rvalue_var < NUM_IPS_OPTIONS_VARS)
    {
        GetVarValueByIndex(&rvalue, config.rvalue_var);
        if (rvalue == 0 and config.oper == BM_DIVIDE)
            return NO_MATCH;
    }
    else
        rvalue = config.rvalue;

    int32_t offset;
    if (config.offset_var >= 0 && config.offset_var < NUM_IPS_OPTIONS_VARS)
    {
        // Rule options variables are kept as uint32_t,
        // in order to support full range for unsigned options.
        // Signed options do a cast to int32_t after getting the value.
        // The range limitation should be taken into consideration when writing a rule
        // with an option that is read from a variable.
        uint32_t extract_offset;
        GetVarValueByIndex(&extract_offset, config.offset_var);
        offset = (int32_t)extract_offset;
    }
    else
        offset = config.offset;

    ptr += offset;

    // check bounds
    if (ptr < start || ptr >= end)
        return NO_MATCH;

    uint8_t endian = config.endianess;
    if (config.endianess == ENDIAN_FUNC)
    {
        if (!p->endianness ||
            !p->endianness->get_offset_endianness(ptr - p->data, endian))
            return NO_MATCH;
    }

    // do the extraction
    int ret, bytes_read;
    uint32_t value;

    if (!config.string_convert_flag)
    {
        ret = byte_extract(endian, config.bytes_to_extract, ptr, start, end, &value);
        if (ret < 0)
            return NO_MATCH;

        bytes_read = config.bytes_to_extract;
    }
    else
    {
        ret = string_extract(config.bytes_to_extract, config.base, ptr, start, end, &value);
        if (ret < 0)
            return NO_MATCH;

        bytes_read = ret;
    }
    /* advance cursor */
    c.add_pos(bytes_read);

    if (config.bitmask_val != 0)
    {
        uint32_t num_tailing_zeros_bitmask = getNumberTailingZerosInBitmask(config.bitmask_val);
        value = value & config.bitmask_val;
        if ( value && num_tailing_zeros_bitmask )
        {
            value = value >> num_tailing_zeros_bitmask;
        }
    }

    // Note: all of the operations are done on uint32_t.
    // If the rule isn't written correctly, there is a risk for wrap around.
    switch (config.oper)
    {
    case BM_PLUS: value += rvalue;
        break;

    case BM_MINUS: value -= rvalue;
        break;

    case BM_MULTIPLY: value *= rvalue;
        break;

    case BM_DIVIDE: value /= rvalue;
        break;

    case BM_LEFT_SHIFT: value <<= rvalue;
        break;

    case BM_RIGHT_SHIFT: value >>= rvalue;
        break;
    }

    SetVarValueByIndex(value, config.result_var);

    return MATCH;
}

//-------------------------------------------------------------------------
// Parsing utils - used by ::set
//-------------------------------------------------------------------------

static void parse_base(uint8_t value, ByteMathData& idx)
{
    assert(value <= 2);
    int base[] = { 16, 10, 8 };
    idx.base = base[value];
}

static void parse_endian(uint8_t value, ByteMathData& idx)
{
    assert(value <= 1);
    int endian[] = { ENDIAN_BIG, ENDIAN_LITTLE };
    set_byte_order(idx.endianess, endian[value], "byte_math");
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "bytes", Parameter::PT_INT, "1:10", nullptr,
      "number of bytes to pick up from the buffer" },

    { "offset", Parameter::PT_STRING, nullptr, nullptr,
      "number of bytes into the buffer to start processing" },

    { "oper", Parameter::PT_ENUM, "+|-|*|/|<<|>>", nullptr,
      "mathematical operation to perform" },

    { "rvalue", Parameter::PT_STRING, nullptr, nullptr,
      "value to use mathematical operation against" },

    { "result", Parameter::PT_STRING, nullptr, nullptr,
      "name of the variable to store the result" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "offset from cursor instead of start of buffer" },

    { "endian", Parameter::PT_ENUM, "big|little", nullptr,
      "specify big/little endian" },

    { "dce", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dcerpc2 determines endianness" },

    { "string", Parameter::PT_ENUM, "hex|dec|oct", nullptr,
      "convert extracted string to dec/hex/oct" },

    { "bitmask", Parameter::PT_INT, "0x1:0xFFFFFFFF", nullptr,
      "applies as bitwise AND to the extracted value before storage in 'name'" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ByteMathModule : public Module
{
public:
    ByteMathModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &byteMathPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    ByteMathData data;
    string rvalue_var;
    string off_var;
};

bool ByteMathModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    rvalue_var.clear();
    off_var.clear();
    return true;
}


bool ByteMathModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("bytes") )
        data.bytes_to_extract = v.get_long();

    else if ( v.is("oper") )
        data.oper = (BM_Oper)v.get_long();

    else if ( v.is("rvalue") )
    {
        long n;
        if ( v.strtol(n) )
        {
            if (n == 0)
                return false;
            data.rvalue = n;
        }
        else
            rvalue_var = v.get_string();
    }
    else if ( v.is("offset") )
    {
        long n;
        if ( v.strtol(n) )
            data.offset = n;
        else
            off_var = v.get_string();
    }
    else if ( v.is("relative") )
        data.relative_flag = true;

    else if ( v.is("dce") )
        set_byte_order(data.endianess, ENDIAN_FUNC, "byte_math");

    else if ( v.is("string") )
    {
        data.string_convert_flag = true;
        parse_base(v.get_long(), data);
    }
    else if ( v.is("endian") )
        parse_endian(v.get_long(), data);

    else if ( v.is("bitmask") )
        data.bitmask_val = v.get_long();

    else if ( v.is("result") )
        data.result_name = snort_strdup(v.get_string());

    else
        return false;

    return true;
}

/* Checks a ByteMathData instance for errors. */
static bool ByteMathVerify(ByteMathData* data)
{
    if (!data->result_name)
    {
        ParseError("result variable missing");
        return false;
    }

    if (isdigit(data->result_name[0]))
    {
        ParseError("byte_math rule option has a name which starts with a digit. "
            "Variable names must start with a letter.");
        return false;
    }

    if ( ((data->oper == BM_LEFT_SHIFT) || (data->oper == BM_RIGHT_SHIFT)) &&
        (data->rvalue > 32))
    {
        ParseError("Number of bits in rvalue input [%u] should be less than 32 "
            "bits for operator", data->rvalue);
        return false;
    }

    if (((data->oper == BM_LEFT_SHIFT) || (data->oper == BM_RIGHT_SHIFT)) &&
        (data->bytes_to_extract > 4))
    {
        ParseError("for operators << and  >> valid bytes_to_extract input range is"
            " 1 to 4 bytes");
        return false;
    }

    if (data->bytes_to_extract > MAX_BYTES_TO_GRAB && !data->string_convert_flag)
    {
        ParseError("byte_math rule option cannot extract more than %d bytes without valid"
            " string prefix.", MAX_BYTES_TO_GRAB);
        return false;
    }

    if (numBytesInBitmask(data->bitmask_val) > data->bytes_to_extract)
    {
        ParseError("Number of bytes in \"bitmask\" value is greater than bytes to extract.");
        return false;
    }

    return true;
}

bool ByteMathModule::end(const char*, int, SnortConfig*)
{
    if ( rvalue_var.empty() )
        data.rvalue_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.rvalue_var = GetVarByName(rvalue_var.c_str());

        if (data.rvalue_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "byte_math", rvalue_var.c_str());
            return false;
        }
    }

    if ( off_var.empty() )
        data.offset_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.offset_var = GetVarByName(off_var.c_str());

        if (data.offset_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "byte_math", off_var.c_str());
            return false;
        }
    }

    if ( !data.endianess )
        data.endianess = ENDIAN_BIG;

    return ByteMathVerify(&data);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ByteMathModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* byte_math_ctor(Module* p, OptTreeNode*)
{
    ByteMathModule* m = (ByteMathModule*)p;
    ByteMathData& data = m->data;

    data.result_var = AddVarNameToList(data.result_name);
    if (data.result_var == IPS_OPTIONS_NO_VAR)
    {
        ParseError("Rule has more than %d variables.",
            NUM_IPS_OPTIONS_VARS);
        return nullptr;
    }
    return new ByteMathOption(m->data);
}

static void byte_math_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi byte_math_api =
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
    byte_math_ctor,
    byte_math_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_byte_math[] =
#endif
{
    &byte_math_api.base,
    nullptr
};
