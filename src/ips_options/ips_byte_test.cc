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

/* byte_test
 * Author: Martin Roesch
 *
 * Purpose:
 *      Test a byte field against a specific value (with opcode).  Capable
 *      of testing binary values or converting representative byte strings
 *      to their binary equivalent and testing them.
 *
 *
 * Arguments:
 *      Required:
 *      <bytes_to_convert>: number of bytes to pick up from the packet
 *      <opcode>: operation to perform to test the value (<,>,=,!)
 *      <value>: value to test the converted value against
 *      <offset>: number of bytes into the payload to start processing
 *      Optional:
 *      ["relative"]: offset relative to last pattern match
 *      ["big"]: process data as big endian (default)
 *      ["little"]: process data as little endian
 *      ["string"]: converted bytes represented as a string needing conversion
 *      ["hex"]: converted string data is represented in hexadecimal
 *      ["dec"]: converted string data is represented in decimal
 *      ["oct"]: converted string data is represented in octal
 *      ["bitmask"]: applies the AND operator on the bytes converted. The
 *                   result will be right-shifted by the number of bits equal
 *                   to the number of trailing zeros in the mask.
 *
 *   sample rules:
 *   alert udp $EXTERNAL_NET any -> $HOME_NET any \
 *      (msg:"AMD procedure 7 plog overflow "; \
 *      content: "|00 04 93 F3|"; \
 *      content: "|00 00 00 07|"; distance: 4; within: 4; \
 *      byte_test: 4,>, 1000, 20, relative;)
 *
 *   alert tcp $EXTERNAL_NET any -> $HOME_NET any \
 *      (msg:"AMD procedure 7 plog overflow "; \
 *      content: "|00 04 93 F3|"; \
 *      content: "|00 00 00 07|"; distance: 4; within: 4; \
 *      byte_test: 4, >,1000, 20, relative;)
 *
 * alert udp any any -> any 1234 \
 *      (byte_test: 4, =, 1234, 0, string, dec; \
 *      msg: "got 1234!";)
 *
 * alert udp any any -> any 1235 \
 *      (byte_test: 3, =, 123, 0, string, dec; \
 *      msg: "got 123!";)
 *
 * alert udp any any -> any 1236 \
 *      (byte_test: 2, =, 12, 0, string, dec; \
 *      msg: "got 12!";)
 *
 * alert udp any any -> any 1237 \
 *      (byte_test: 10, =, 1234567890, 0, string, dec; \
 *      msg: "got 1234567890!";)
 *
 * alert udp any any -> any 1238 \
 *      (byte_test: 8, =, 0xdeadbeef, 0, string, hex; \
 *      msg: "got DEADBEEF!";)
 *
 * alert tcp any any -> any any \
 *      (byte_test:2, =, 568, 0, bitmask 0x3FF0;	  \
 *      msg:"got 568 after applying bitmask 0x3FF0 on 2 bytes extracted";)
 *
 * Effect:
 *
 *      Reads in the indicated bytes, converts them to an numeric
 *      representation and then performs the indicated operation/test on
 *      the data using the value field.  Returns 1 if the operation is true,
 *      0 if it is not.
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
#include "utils/util.h"

#include "extract.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL ProfileStats byteTestPerfStats;

#define s_name "byte_test"

enum ByteTestOper
{
    CHECK_EQ,
    CHECK_LT,
    CHECK_GT,
    CHECK_LTE,
    CHECK_GTE,
    CHECK_AND,
    CHECK_XOR
};

struct ByteTestData
{
    uint32_t bytes_to_compare;
    uint32_t cmp_value;
    ByteTestOper opcode;
    int32_t offset;
    bool not_flag;
    bool relative_flag;
    bool data_string_convert_flag;
    uint8_t endianness;
    uint32_t base;
    uint32_t bitmask_val;
    int8_t cmp_value_var;
    int8_t offset_var;
};

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------

static inline bool byte_test_check(ByteTestOper op, uint32_t val, uint32_t cmp, bool not_flag)
{
    bool success = false;

    switch ( op )
    {
    case CHECK_LT:
        success = (val < cmp);
        break;

    case CHECK_EQ:
        success = (val == cmp);
        break;

    case CHECK_GT:
        success = (val > cmp);
        break;

    case CHECK_AND:
        success = ((val & cmp) > 0);
        break;

    case CHECK_XOR:
        success = ((val ^ cmp) > 0);
        break;

    case CHECK_GTE:
        success = (val >= cmp);
        break;

    case CHECK_LTE:
        success = (val <= cmp);
        break;
    }

    if ( not_flag )
    {
        success = !success;
    }

    return success;
}

class ByteTestOption : public IpsOption
{
public:
    ByteTestOption(const ByteTestData& c) : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_relative() override
    { return config.relative_flag; }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    ByteTestData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteTestOption::hash() const
{
    uint32_t a,b,c;
    const ByteTestData* data = &config;

    a = data->bytes_to_compare;
    b = data->cmp_value;
    c = data->opcode;

    mix(a,b,c);

    a += data->offset;
    b += data->not_flag ? (1 << 24) : 0;
    b += data->relative_flag ? (1 << 16) : 0;
    b += data->data_string_convert_flag ? (1 << 8) : 0;
    b += data->endianness;
    c += data->base;

    mix(a,b,c);

    a += data->cmp_value_var;
    b += data->offset_var;
    c += data->bitmask_val;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool ByteTestOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const ByteTestOption& rhs = (const ByteTestOption&)ips;
    const ByteTestData* left = &config;
    const ByteTestData* right = &rhs.config;

    if (( left->bytes_to_compare == right->bytes_to_compare) &&
        ( left->cmp_value == right->cmp_value) &&
        ( left->opcode == right->opcode) &&
        ( left->offset == right->offset) &&
        ( left->not_flag == right->not_flag) &&
        ( left->relative_flag == right->relative_flag) &&
        ( left->data_string_convert_flag == right->data_string_convert_flag) &&
        ( left->endianness == right->endianness) &&
        ( left->base == right->base) &&
        ( left->cmp_value_var == right->cmp_value_var) &&
        ( left->offset_var == right->offset_var) &&
        ( left->bitmask_val == right->bitmask_val))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus ByteTestOption::eval(Cursor& c, Packet* p)
{
    Profile profile(byteTestPerfStats);

    ByteTestData* btd = (ByteTestData*)&config;
    uint32_t cmp_value = 0;

    // Get values from byte_extract variables, if present.
    if (btd->cmp_value_var >= 0 && btd->cmp_value_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t val;
        GetVarValueByIndex(&val, btd->cmp_value_var);
        cmp_value = val;
    }
    else
        cmp_value = btd->cmp_value;

    int offset = 0;

    if (btd->offset_var >= 0 && btd->offset_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t val;
        GetVarValueByIndex(&val, btd->offset_var);
        offset = (int32_t)val;
    }
    else
        offset = btd->offset;

    const uint8_t* start_ptr = btd->relative_flag ? c.start() : c.buffer();
    start_ptr += offset;

    uint8_t endian = btd->endianness;
    if (endian == ENDIAN_FUNC)
    {
        if (!p->endianness ||
            !p->endianness->get_offset_endianness(start_ptr - p->data, endian))
            return NO_MATCH;
    }

    uint32_t value = 0;

    if (!btd->data_string_convert_flag)
    {
        if ( byte_extract(
            endian, btd->bytes_to_compare,
            start_ptr, c.buffer(), c.endo(), &value))
            return NO_MATCH;
    }
    else
    {
        unsigned len = btd->relative_flag ? c.length() : c.size();

        if ( len > btd->bytes_to_compare )
            len = btd->bytes_to_compare;

        int payload_bytes_grabbed = string_extract(
            len, btd->base, start_ptr, c.buffer(), c.endo(), &value);

        if ( payload_bytes_grabbed < 0 )
        {
            return NO_MATCH;
        }
    }

    if (btd->bitmask_val != 0 )
    {
        uint32_t num_tailing_zeros_bitmask = getNumberTailingZerosInBitmask(btd->bitmask_val);
        value = value & btd->bitmask_val;
        if ( value && num_tailing_zeros_bitmask )
        {
            value = value >> num_tailing_zeros_bitmask;
        }
    }

    if ( byte_test_check(btd->opcode, value, cmp_value, btd->not_flag) )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static void parse_operator(const char* oper, ByteTestData& idx)
{
    const char* cptr = oper;

    if (*cptr == '!')
    {
        idx.not_flag = true;
        cptr++;
    }

    if (idx.not_flag && strlen(cptr) == 0)
    {
        idx.opcode = CHECK_EQ;
    }
    else
    {
        /* set the opcode */
        switch (*cptr)
        {
        case '<':
            idx.opcode = CHECK_LT;
            cptr++;
            if (*cptr == '=')
                idx.opcode = CHECK_LTE;
            else
                cptr--;
            break;

        case '=':
            idx.opcode = CHECK_EQ;
            break;

        case '>':
            idx.opcode = CHECK_GT;
            cptr++;
            if (*cptr == '=')
                idx.opcode = CHECK_GTE;
            else
                cptr--;
            break;

        case '&':
            idx.opcode = CHECK_AND;
            break;

        case '^':
            idx.opcode = CHECK_XOR;
            break;

        default:
            ParseError("byte_test unknown operator (%s)", oper);
            return;
        }

        cptr++;
        if (strlen(cptr))
            ParseError("byte_test unknown operator (%s)", oper);
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~count", Parameter::PT_INT, "1:10", nullptr,
      "number of bytes to pick up from the buffer" },

    { "~operator", Parameter::PT_STRING, nullptr, nullptr,
      "operation to perform to test the value" },

    { "~compare", Parameter::PT_STRING, nullptr, nullptr,
      "variable name or value to test the converted result against" },

    { "~offset", Parameter::PT_STRING, nullptr, nullptr,
      "variable name or number of bytes into the payload to start processing" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "offset from cursor instead of start of buffer" },

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
    "rule option to convert data to integer and compare"

class ByteTestModule : public Module
{
public:
    ByteTestModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &byteTestPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    ByteTestData data;
    string cmp_var;
    string off_var;
};

bool ByteTestModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    cmp_var.clear();
    off_var.clear();
    return true;
}

bool ByteTestModule::end(const char*, int, SnortConfig*)
{
    if ( off_var.empty() )
        data.offset_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.offset_var = GetVarByName(off_var.c_str());

        if (data.offset_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "byte_test", off_var.c_str());
            return false;
        }
    }
    if ( cmp_var.empty() )
        data.cmp_value_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.cmp_value_var = GetVarByName(cmp_var.c_str());

        if (data.cmp_value_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "byte_test", cmp_var.c_str());
            return false;
        }
    }
    if ( !data.endianness )
        data.endianness = ENDIAN_BIG;

    if (numBytesInBitmask(data.bitmask_val) > data.bytes_to_compare)
    {
        ParseError("Number of bytes in \"bitmask\" value is greater than bytes to extract.");
        return false;
    }

    return true;
}

bool ByteTestModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~count") )
        data.bytes_to_compare = v.get_long();

    else if ( v.is("~operator") )
        parse_operator(v.get_string(), data);

    else if ( v.is("~compare") )
    {
        long n;
        if ( v.strtol(n) )
            data.cmp_value = n;
        else
            cmp_var = v.get_string();
    }
    else if ( v.is("~offset") )
    {
        long n;
        if ( v.strtol(n) )
            data.offset = n;
        else
            off_var = v.get_string();
    }
    else if ( v.is("relative") )
        data.relative_flag = true;

    else if ( v.is("big") )
        set_byte_order(data.endianness, ENDIAN_BIG, "byte_test");

    else if ( v.is("little") )
        set_byte_order(data.endianness, ENDIAN_LITTLE, "byte_test");

    else if ( v.is("dce") )
        set_byte_order(data.endianness, ENDIAN_FUNC, "byte_test");

    else if ( v.is("string") )
    {
        data.data_string_convert_flag = true;
        data.base = 10;
    }
    else if ( v.is("dec") )
        data.base = 10;

    else if ( v.is("hex") )
        data.base = 16;

    else if ( v.is("oct") )
        data.base = 8;

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
    return new ByteTestModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* byte_test_ctor(Module* p, OptTreeNode*)
{
    ByteTestModule* m = (ByteTestModule*)p;
    return new ByteTestOption(m->data);
}

static void byte_test_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi byte_test_api =
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
    byte_test_ctor,
    byte_test_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_byte_test[] =
#endif
{
    &byte_test_api.base,
    nullptr
};

