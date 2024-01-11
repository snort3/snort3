//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
 *      (byte_test:2, =, 568, 0, bitmask 0x3FF0;      \
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
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include <climits>
#include "catch/snort_catch.h"
#endif

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

struct ByteTestData : public ByteData
{
    uint32_t cmp_value;
    ByteTestOper opcode;
    bool not_flag;
    int8_t cmp_value_var;
    int8_t offset_var;
};

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------

static inline bool byte_test_check(ByteTestOper op, uint32_t val, uint32_t cmp,
    bool not_flag)
{
    bool success = false;

    switch ( op )
    {
    case CHECK_EQ:
        success = (val == cmp);
        break;

    case CHECK_LT:
        success = (val < cmp);
        break;

    case CHECK_GT:
        success = (val > cmp);
        break;

    case CHECK_LTE:
        success = (val <= cmp);
        break;

    case CHECK_GTE:
        success = (val >= cmp);
        break;

    case CHECK_AND:
        success = ((val & cmp) > 0);
        break;

    case CHECK_XOR:
        success = ((val ^ cmp) > 0);
        break;
    }

    if (not_flag)
    {
        success = !success;
    }

    return success;
}

class ByteTestOption : public IpsOption
{
public:
    ByteTestOption(const ByteTestData& c) : IpsOption(s_name), config(c) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_relative() override
    { return config.relative_flag; }

    EvalStatus eval(Cursor&, Packet*) override;

    CursorActionType get_cursor_type() const override
    { return CAT_READ; }

private:
    ByteTestData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteTestOption::hash() const
{
    uint32_t a = config.bytes_to_extract;
    uint32_t b = config.cmp_value;
    uint32_t c = config.opcode;

    mix(a,b,c);

    a += config.offset;
    b += config.not_flag ? (1 << 24) : 0;
    b += config.relative_flag ? (1 << 16) : 0;
    b += config.string_convert_flag ? (1 << 8) : 0;
    b += config.endianness;
    c += config.base;

    mix(a,b,c);

    a += config.cmp_value_var;
    b += config.offset_var;
    c += config.bitmask_val;

    mix(a,b,c);
    a += IpsOption::hash();

    mix(a,b,c);
    finalize(a,b,c);

    return c;
}

bool ByteTestOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const ByteTestOption& rhs = (const ByteTestOption&)ips;
    const ByteTestData* left = &config;
    const ByteTestData* right = &rhs.config;

    if (( left->bytes_to_extract == right->bytes_to_extract) and
        ( left->cmp_value == right->cmp_value) and
        ( left->opcode == right->opcode) and
        ( left->offset == right->offset) and
        ( left->not_flag == right->not_flag) and
        ( left->relative_flag == right->relative_flag) and
        ( left->string_convert_flag == right->string_convert_flag) and
        ( left->endianness == right->endianness) and
        ( left->base == right->base) and
        ( left->cmp_value_var == right->cmp_value_var) and
        ( left->offset_var == right->offset_var) and
        ( left->bitmask_val == right->bitmask_val))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus ByteTestOption::eval(Cursor& c, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(byteTestPerfStats);

    ByteTestData* btd = (ByteTestData*)&config;
    uint32_t cmp_value = 0;

    // Get values from byte_extract variables, if present.
    if (btd->cmp_value_var >= 0 and btd->cmp_value_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t val;
        GetVarValueByIndex(&val, btd->cmp_value_var);
        cmp_value = val;
    }
    else
        cmp_value = btd->cmp_value;

    int offset = 0;

    if (btd->offset_var >= 0 and btd->offset_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t val;
        GetVarValueByIndex(&val, btd->offset_var);
        offset = (int32_t)val;
    }
    else
        offset = btd->offset;

    ByteTestData extract_config = *btd;
    extract_config.offset = offset;

    uint32_t value = 0;
    int32_t payload_bytes_grabbed = extract_data(extract_config, c, p, value);

    if (payload_bytes_grabbed == NO_MATCH)
        return NO_MATCH;

    if (byte_test_check(btd->opcode, value, cmp_value, btd->not_flag))
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

    if (idx.not_flag and strlen(cptr) == 0)
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
      "number of bytes to pick up from the buffer (string can pick less)" },

    { "~operator", Parameter::PT_STRING, nullptr, nullptr,
      "operation to perform to test the value" },

    { "~compare", Parameter::PT_STRING, nullptr, nullptr,
      "variable name or value to test the converted result against" },

    { "~offset", Parameter::PT_STRING, nullptr, nullptr,
      "variable name or number of bytes into the payload to start processing"},

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
    ByteTestData data = {};
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
    if (off_var.empty())
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
    if (cmp_var.empty())
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
    if (!data.endianness)
        data.endianness = ENDIAN_BIG;

    if (numBytesInBitmask(data.bitmask_val) > data.bytes_to_extract)
    {
        ParseError("Number of bytes in \"bitmask\" value is greater " \
            "than bytes to extract.");
        return false;
    }

    return true;
}

bool ByteTestModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("~count"))
        data.bytes_to_extract = v.get_uint8();

    else if (v.is("~operator"))
        parse_operator(v.get_string(), data);

    else if (v.is("~compare"))
    {
        unsigned long n;
        if (v.strtoul(n))
            data.cmp_value = n;
        else
            cmp_var = v.get_string();
    }
    else if (v.is("~offset"))
    {
        long n;
        if (v.strtol(n))
            data.offset = n;
        else
            off_var = v.get_string();
    }
    else if (v.is("relative"))
        data.relative_flag = true;

    else if (v.is("big"))
        set_byte_order(data.endianness, ENDIAN_BIG, "byte_test");

    else if (v.is("little"))
        set_byte_order(data.endianness, ENDIAN_LITTLE, "byte_test");

    else if (v.is("dce"))
        set_byte_order(data.endianness, ENDIAN_FUNC, "byte_test");

    else if (v.is("string"))
    {
        data.string_convert_flag = true;
        data.base = 10;
    }
    else if (v.is("dec"))
        data.base = 10;

    else if (v.is("hex"))
        data.base = 16;

    else if (v.is("oct"))
        data.base = 8;

    else if (v.is("bitmask"))
        data.bitmask_val = v.get_uint32();

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

//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------
#ifdef UNIT_TEST
#include <climits>

#include "catch/snort_catch.h"

#define NO_MATCH snort::IpsOption::EvalStatus::NO_MATCH
#define MATCH snort::IpsOption::EvalStatus::MATCH

static void SetByteTestData(ByteTestData &byte_test, int value, ByteTestOper code = CHECK_EQ)
{
    byte_test.bytes_to_extract = value;
    byte_test.cmp_value = value;
    byte_test.opcode = code;
    byte_test.offset = value;
    byte_test.not_flag = value;
    byte_test.relative_flag = value;
    byte_test.string_convert_flag = value;
    byte_test.endianness = value;
    byte_test.base = value;
    byte_test.bitmask_val = value;
    byte_test.cmp_value_var = value;
    byte_test.offset_var = value;
}

static void SetByteTestDataMax(ByteTestData& byte_test)
{
    byte_test.bytes_to_extract = UINT_MAX;
    byte_test.cmp_value = UINT_MAX;
    byte_test.opcode = CHECK_XOR;
    byte_test.offset = INT_MAX;
    byte_test.not_flag = true;
    byte_test.relative_flag = true;
    byte_test.string_convert_flag = true;
    byte_test.endianness = UCHAR_MAX;
    byte_test.base = UINT_MAX;
    byte_test.bitmask_val = UINT_MAX;
    byte_test.cmp_value_var = CHAR_MAX;
    byte_test.offset_var = CHAR_MAX;
}

class StubEndianness : public Endianness
{
public:
    StubEndianness() = default;
    virtual bool get_offset_endianness(int32_t, uint8_t& ) override
    { return false; }
};

TEST_CASE("byte_test_check test", "[ips_byte_test]")
{
    SECTION("Incorrect ByteTestOper, other data correct")
    {
        REQUIRE(false == byte_test_check(ByteTestOper(7), 1, 1, 0));
    }

    SECTION("Incorrect ByteTestOper, true not_flag")
    {
        REQUIRE(true == byte_test_check(ByteTestOper(7), 1, 1, 1));
    }

    SECTION("CHECK_EQ both true && false situation")
    {
        REQUIRE(true == byte_test_check(ByteTestOper(0), 1, 1, 0));
        REQUIRE(false == byte_test_check(ByteTestOper(0), 1, 2, 0));
    }

    SECTION("CHECK_LT both true && false situation")
    {
        REQUIRE(true == byte_test_check(ByteTestOper(1), 1, 2, 0));
        REQUIRE(false == byte_test_check(ByteTestOper(1), 4, 1, 0));
    }

    SECTION("CHECK_GT both true && false situation")
    {
        REQUIRE(true == byte_test_check(ByteTestOper(2), 2, 1, 0));
        REQUIRE(false == byte_test_check(ByteTestOper(2), 1, 4, 0));
    }

    SECTION("CHECK_LTE both true && false situation")
    {
        REQUIRE(true == byte_test_check(ByteTestOper(3), 0, 1, 0));
        REQUIRE(false == byte_test_check(ByteTestOper(3), 4, 1, 0));
    }

    SECTION("CHECK_GTE both true && false situation")
    {
        REQUIRE(true == byte_test_check(ByteTestOper(4), 1, 0, 0));
        REQUIRE(false == byte_test_check(ByteTestOper(4), 0, 4, 0));
    }

    SECTION("CHECK_AND for bites both true && false situation")
    {
        REQUIRE(true == byte_test_check(ByteTestOper(5), 1, 1, 0));
        REQUIRE(false == byte_test_check(ByteTestOper(5), 1, 0, 0));
    }

    SECTION("CHECK_XOR for bites both true && false situation")
    {
        REQUIRE(true == byte_test_check(ByteTestOper(6), 1, 0, 0));
        REQUIRE(false == byte_test_check(ByteTestOper(6), 1, 1, 0));
    }
}

TEST_CASE("ByteTestOption test", "[ips_byte_test]")
{
    ByteTestData byte_test;
    SetByteTestData(byte_test, 1);

    SECTION("method hash")
    {
        ByteTestOption hash_test(byte_test);
        ByteTestOption hash_test_equal(byte_test);

        SECTION("Testing hash with very low values")
        {
            SECTION("Hash has same source")
            {
                CHECK(hash_test.hash() == hash_test_equal.hash());
            }

            SECTION("Compare hash from different source")
            {
                SetByteTestData(byte_test, 4);
                ByteTestOption hash_test_diff(byte_test);
                CHECK(hash_test.hash() != hash_test_diff.hash());
            }
        }

        SECTION("Testing hash with maximum values")
        {
            SetByteTestDataMax(byte_test);
            ByteTestOption hash_test_max(byte_test);
            ByteTestOption hash_test_equal_max(byte_test);

            SECTION("Hash has same source")
            {
                CHECK(hash_test_max.hash() == hash_test_equal_max.hash());
            }

            SECTION("Testing hash with maximum values from different source")
            {
                SetByteTestDataMax(byte_test);
                ByteTestOption tmp_hash_test_max(byte_test);
                CHECK(hash_test.hash() != tmp_hash_test_max.hash());
            }
        }
    }

    SECTION("operator ==")
    {
        ByteTestOption test(byte_test);

        SECTION("Compare between equals objects")
        {
            ByteTestOption test_1(byte_test);
            REQUIRE(test == test_1);
        }

        SECTION("byte_to_compare is different")
        {
            byte_test.bytes_to_extract = 2;
            ByteTestOption test_2_1(byte_test);
            REQUIRE(test != test_2_1);
        }

        SECTION("cmp_value is different")
        {
            byte_test.cmp_value = 2;
            ByteTestOption test_2_2(byte_test);
            REQUIRE(test != test_2_2);
        }

        SECTION("cmp_value is different")
        {
            byte_test.opcode = CHECK_LT;
            ByteTestOption test_2_3(byte_test);
            REQUIRE(test != test_2_3);
        }

        SECTION("offset is different")
        {
            byte_test.offset = 2;
            ByteTestOption test_2_4(byte_test);
            REQUIRE(test != test_2_4);
        }

        SECTION("not_flag is different")
        {
            byte_test.not_flag = 0;
            ByteTestOption test_2_5(byte_test);
            REQUIRE(test != test_2_5);
        }

        SECTION("relative_flag is different")
        {
            byte_test.relative_flag = 0;
            ByteTestOption test_2_6(byte_test);
            REQUIRE(test != test_2_6);
        }

        SECTION("string_convert_flag is different")
        {
            byte_test.string_convert_flag = 0;
            ByteTestOption test_2_7(byte_test);
            REQUIRE(test != test_2_7);
        }

        SECTION("endianness is different")
        {
            byte_test.endianness = 0;
            ByteTestOption test_2_8(byte_test);
            REQUIRE(test != test_2_8);
        }

        SECTION("base is different")
        {
            byte_test.base = 2;
            ByteTestOption test_2_9(byte_test);
            REQUIRE(test != test_2_9);
        }

        SECTION("bitmask_val is different")
        {
            byte_test.bitmask_val = 2;
            ByteTestOption test_2_10(byte_test);
            REQUIRE(test != test_2_10);
        }

        SECTION("cmp_value_var is different")
        {
            byte_test.cmp_value_var = 0;
            ByteTestOption test_2_13(byte_test);
            REQUIRE(test != test_2_13);
        }

        SECTION("cmp_value_var is different")
        {
            byte_test.offset_var = 0;
            ByteTestOption test_2_12(byte_test);
            REQUIRE(test != test_2_12);
        }
    }

    SECTION("method eval")
    {
        Packet test_packet;
        Cursor current_cursor;
        SetByteTestData(byte_test, 1);

        SECTION("Cursor not set correct for byte_extract")
        {
            byte_test.cmp_value_var = 3;
            byte_test.offset_var = 3;
            byte_test.string_convert_flag = 0;
            ByteTestOption test_2(byte_test);
            REQUIRE((test_2.eval(current_cursor, &test_packet)) == NO_MATCH);
        }

        SECTION("Byte_to_compare set to zero for string_extract")
        {
            byte_test.string_convert_flag = 1;
            byte_test.bytes_to_extract = 0;
            ByteTestOption test_3(byte_test);
            uint8_t buff = 0;
            current_cursor.set("hello_world_long_name", &buff, 50);
            REQUIRE((test_3.eval(current_cursor, &test_packet)) == NO_MATCH);
        }

        SECTION("Byte_test_check with extract value not equal to need one")
        {
            byte_test.string_convert_flag = 0;
            byte_test.relative_flag = 0;
            uint8_t buff = 0;
            current_cursor.set("hello_world_long_name", &buff, 50);
            ByteTestOption test_4(byte_test);
            REQUIRE((test_4.eval(current_cursor, &test_packet)) == NO_MATCH);
        }

        SECTION("Correct match")
        {
            byte_test.string_convert_flag = 0;
            byte_test.relative_flag = 0;
            byte_test.opcode = ByteTestOper(7);
            byte_test.not_flag = 1;
            uint8_t buff = 0;
            current_cursor.set("hello_world_long_name", &buff, 50);
            ByteTestOption test_5(byte_test);
            REQUIRE((test_5.eval(current_cursor, &test_packet)) == MATCH);
        }

        SECTION("bytes_to_extract bigger than amount of bytes left in the buffer")
        {
            byte_test.offset = 0;
            byte_test.offset_var = -1;
            byte_test.bytes_to_extract = 3;
            byte_test.string_convert_flag = 0;
            byte_test.relative_flag = 1;
            uint8_t buff[] = "Hello world long input";
            current_cursor.set("hello_world_long_name", buff, 22);
            current_cursor.set_pos(20);
            ByteTestOption test_6(byte_test);
            REQUIRE((test_6.eval(current_cursor, &test_packet)) == NO_MATCH);
        }

        SECTION("String truncation")
        {
            byte_test.cmp_value = 123;
            byte_test.cmp_value_var = -1;
            byte_test.bytes_to_extract = 10;
            byte_test.opcode = ByteTestOper(0);
            byte_test.offset = 0;
            byte_test.offset_var = -1;
            byte_test.string_convert_flag = 1;
            byte_test.relative_flag = 1;
            byte_test.bitmask_val = 0;
            byte_test.not_flag = 0;
            byte_test.base = 10;
            uint8_t buff[] = "Hello world long input 123";
            current_cursor.set("hello_world_long_name", buff, 26);
            current_cursor.set_pos(23);
            ByteTestOption test_7(byte_test);
            REQUIRE((test_7.eval(current_cursor, &test_packet)) == MATCH);
        }

        SECTION("Negative offset")
        {
            SECTION("Cursor on the last byte of buffer")
            {
                byte_test.cmp_value = 32;
                byte_test.cmp_value_var = -1;
                byte_test.bytes_to_extract = 1;
                byte_test.opcode = ByteTestOper(0);
                byte_test.offset = -6;
                byte_test.offset_var = -1;
                byte_test.string_convert_flag = 0;
                byte_test.relative_flag = 1;
                byte_test.bitmask_val = 0;
                byte_test.not_flag = 0;
                uint8_t buff[] = "Hello world long input";
                current_cursor.set("hello_world_long_name", buff, 22);
                current_cursor.set_pos(22);
                ByteTestOption test_8(byte_test);
                REQUIRE((test_8.eval(current_cursor, &test_packet)) == MATCH);
            }

            SECTION("Cursor on the last byte of buffer, bytes_to_extract is bigger than offset")
            {
                byte_test.bytes_to_extract = 4;
                byte_test.offset = -3;
                byte_test.offset_var = -1;
                byte_test.relative_flag = 1;
                byte_test.string_convert_flag = 0;
                uint8_t buff[] = "Hello world long input";
                current_cursor.set("hello_world_long_name", buff, 22);
                current_cursor.set_pos(22);
                ByteTestOption test_9(byte_test);
                REQUIRE((test_9.eval(current_cursor, &test_packet)) == NO_MATCH);
            }

            SECTION("Cursor on the last byte of buffer with string flag")
            {
                byte_test.cmp_value = 123;
                byte_test.cmp_value_var = -1;
                byte_test.bytes_to_extract = 3;
                byte_test.opcode = ByteTestOper(0);
                byte_test.offset = -3;
                byte_test.offset_var = -1;
                byte_test.string_convert_flag = 1;
                byte_test.relative_flag = 1;
                byte_test.bitmask_val = 0;
                byte_test.not_flag = 0;
                byte_test.base = 10;
                uint8_t buff[] = "Hello world long input 123";
                current_cursor.set("hello_world_long_name", buff, 26);
                current_cursor.set_pos(26);
                ByteTestOption test_10(byte_test);
                REQUIRE((test_10.eval(current_cursor, &test_packet)) == MATCH);
            }

            SECTION("String truncation")
            {
                byte_test.cmp_value = 123;
                byte_test.cmp_value_var = -1;
                byte_test.bytes_to_extract = 10;
                byte_test.opcode = ByteTestOper(0);
                byte_test.offset = -3;
                byte_test.offset_var = -1;
                byte_test.string_convert_flag = 1;
                byte_test.relative_flag = 1;
                byte_test.bitmask_val = 0;
                byte_test.not_flag = 0;
                byte_test.base = 10;
                uint8_t buff[] = "Hello world long input 123";
                current_cursor.set("hello_world_long_name", buff, 26);
                current_cursor.set_pos(26);
                ByteTestOption test_11(byte_test);
                REQUIRE((test_11.eval(current_cursor, &test_packet)) == MATCH);
            }
        }
    }
}

TEST_CASE("ByteTestModule test", "[ips_byte_test]")
{
    ByteTestModule module_test;
    ByteTestData byte_test;
    SetByteTestData(byte_test, 1);

    SECTION("method end")
    {
        std::string buff = "tmp";

        SECTION("Undefined rule option for var")
        {
            module_test.cmp_var = buff;
            module_test.data = byte_test;
            REQUIRE(false == module_test.end("tmp", 0, nullptr));
        }

        SECTION("Undefined rule option for offset_var")
        {
            module_test.cmp_var.clear();
            module_test.off_var = buff;
            module_test.data = byte_test;
            REQUIRE(false == module_test.end("tmp", 0, nullptr));
        }

        SECTION("Number of bytes in \"bitmask\" value is greater than bytes to extract")
        {
            byte_test.endianness = 0;
            byte_test.bytes_to_extract = 0;
            module_test.data = byte_test;
            REQUIRE(false == module_test.end("tmp", 0, nullptr));
        }

        SECTION("Case with returned value true")
        {
            module_test.data = byte_test;
            REQUIRE(true == module_test.end("tmp", 0, nullptr));
        }
    }

    SECTION("method set")
    {
        Value value(false);

        SECTION("Case param \"~count\"")
        {
            Parameter param("~count", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Param \"~operator\" correct")
        {
            Parameter param("~operator", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Case param \"~compare\"")
        {
            SECTION("Value doesn't have a str")
            {
                Parameter param("~compare", snort::Parameter::Type::PT_BOOL,
                    nullptr, "default", "help");
                value.set(&param);
                REQUIRE(true == module_test.set(nullptr, value, nullptr));
            }

            SECTION("When value has a str")
            {
                Value value_tmp("123");
                Parameter param("~compare", snort::Parameter::Type::PT_BOOL,
                    nullptr, "default", "help");
                value_tmp.set(&param);
                REQUIRE(true == module_test.set(nullptr, value_tmp, nullptr));
            }

            SECTION("Value isn't truncated")
            {
                Value value_tmp("4294967295");
                Parameter param("~compare", snort::Parameter::Type::PT_BOOL,
                    nullptr, "default", "help");
                value_tmp.set(&param);
                REQUIRE(true == module_test.set(nullptr, value_tmp, nullptr));
                REQUIRE(module_test.data.cmp_value == 4294967295UL);
            }
        }

        SECTION("Case param \"~offset\"")
        {
            SECTION("Value doesn't have a str")
            {
                Parameter param("~offset", snort::Parameter::Type::PT_BOOL,
                    nullptr, "default", "help");
                value.set(&param);
                REQUIRE(true == module_test.set(nullptr, value, nullptr));
            }

            SECTION("When value has a str")
            {
                Value value_tmp("123");
                Parameter param("~offset", snort::Parameter::Type::PT_BOOL,
                    nullptr, "default", "help");
                value_tmp.set(&param);
                REQUIRE(true == module_test.set(nullptr, value_tmp, nullptr));
            }
        }

        SECTION("Case param \"relative\"")
        {
            Parameter param("relative", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Case param \"big\"")
        {
            Parameter param("big", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Case param \"little\"")
        {
            Parameter param("little", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Case param \"dce\"")
        {
            Parameter param("dce", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Case param \"string\"")
        {
            Parameter param("string", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Case param \"dec\"")
        {
            Parameter param("dec", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Case param \"hex\"")
        {
            Parameter param("hex", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Case param \"oct\"")
        {
            Parameter param("oct", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }

        SECTION("Case param \"bitmask\"")
        {
            Parameter param("bitmask", snort::Parameter::Type::PT_BOOL,
                nullptr, "default", "help");
            value.set(&param);
            REQUIRE(true == module_test.set(nullptr, value, nullptr));
        }
    }
}

#endif
