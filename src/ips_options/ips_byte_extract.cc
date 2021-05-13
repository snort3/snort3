//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
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
// Author: Ryan Jordan <ryan.jordan@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/treenodes.h"
#include "framework/cursor.h"
#include "framework/endianness.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "utils/util.h"

#include "extract.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#include "service_inspectors/dce_rpc/dce_common.h"
#endif

using namespace snort;

static THREAD_LOCAL ProfileStats byteExtractPerfStats;

#define s_name "byte_extract"

#define s_help \
    "rule option to convert data to an integer variable"


struct ByteExtractData
{
    uint32_t bytes_to_grab;
    int32_t offset;
    uint8_t relative_flag;
    uint8_t data_string_convert_flag;
    uint8_t align;
    uint8_t endianness;
    uint32_t base;
    uint32_t multiplier;
    uint32_t bitmask_val;
    int8_t var_number;
    char* name;
};

class ByteExtractOption : public IpsOption
{
public:
    ByteExtractOption(const ByteExtractData& c) : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE)
    { config = c; }

    ~ByteExtractOption() override
    { snort_free(config.name); }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return (config.relative_flag == 1); }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    ByteExtractData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteExtractOption::hash() const
{
    uint32_t a = config.bytes_to_grab;
    uint32_t b = config.offset;
    uint32_t c = config.base;

    mix(a,b,c);

    a += (config.relative_flag << 24 |
        config.data_string_convert_flag << 16 |
        config.align << 8 |
        config.endianness);
    b += config.multiplier;
    c += config.var_number;

    mix(a,b,c);

    a += config.bitmask_val;
    b += IpsOption::hash();

    mix(a,b,c);
    finalize(a,b,c);

    return c;
}

bool ByteExtractOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const ByteExtractOption& rhs = (const ByteExtractOption&)ips;
    const ByteExtractData* left = &config;
    const ByteExtractData* right = &rhs.config;

    if ((left->bytes_to_grab == right->bytes_to_grab) &&
        (left->offset == right->offset) &&
        (left->relative_flag == right->relative_flag) &&
        (left->data_string_convert_flag == right->data_string_convert_flag) &&
        (left->align == right->align) &&
        (left->endianness == right->endianness) &&
        (left->base == right->base) &&
        (left->multiplier == right->multiplier) &&
        (left->var_number == right->var_number) &&
        (left->bitmask_val == right->bitmask_val))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus ByteExtractOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(byteExtractPerfStats);

    ByteExtractData* data = &config;

    if (data == nullptr || p == nullptr)
        return NO_MATCH;

    const uint8_t* start = c.buffer();
    int dsize = c.size();

    const uint8_t* ptr = data->relative_flag ? c.start() : c.buffer();
    ptr += data->offset;

    const uint8_t* end = start + dsize;

    // check bounds
    if (ptr < start || ptr >= end)
        return NO_MATCH;

    uint8_t endian = data->endianness;
    if (data->endianness == ENDIAN_FUNC)
    {
        if (!p->endianness ||
            !p->endianness->get_offset_endianness(ptr - p->data, endian))
            return NO_MATCH;
    }

    // do the extraction
    int ret = 0;
    int bytes_read = 0;
    uint32_t value;
    if (data->data_string_convert_flag == 0)
    {
        ret = byte_extract(endian, data->bytes_to_grab, ptr, start, end, &value);
        if (ret < 0)
            return NO_MATCH;

        bytes_read = data->bytes_to_grab;
    }
    else
    {
        ret = string_extract(data->bytes_to_grab, data->base, ptr, start, end, &value);
        if (ret < 0)
            return NO_MATCH;

        bytes_read = ret;
    }

    if (data->bitmask_val != 0 )
    {
        uint32_t num_tailing_zeros_bitmask = getNumberTailingZerosInBitmask(data->bitmask_val);
        value = value & data->bitmask_val;
        if ( value && num_tailing_zeros_bitmask )
        {
            value = value >> num_tailing_zeros_bitmask;
        }
    }

    /* multiply */
    value *= data->multiplier;

    /* align to next 32-bit or 16-bit boundary */
    if ((data->align == 4) && (value % 4))
    {
        value = value + 4 - (value % 4);
    }
    else if ((data->align == 2) && (value % 2))
    {
        value = value + 2 - (value % 2);
    }

    SetVarValueByIndex(value, data->var_number);

    /* advance cursor */
    c.add_pos(data->offset + bytes_read);

    /* this rule option always "matches" if the read is performed correctly */
    return MATCH;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

/* Checks a ByteExtractData instance for errors. */
static bool ByteExtractVerify(ByteExtractData* data)
{
    if (data->bytes_to_grab > MAX_BYTES_TO_GRAB && data->data_string_convert_flag == 0)
    {
        ParseError("byte_extract rule option cannot extract more than %d bytes.",
            MAX_BYTES_TO_GRAB);
        return false;
    }

    if (data->bytes_to_grab > PARSELEN && data->data_string_convert_flag == 1)
    {
        ParseError("byte_extract rule cannot process more than %d bytes for "
            "string extraction.",  PARSELEN);
        return false;
    }

    if (data->align != 0 && data->align != 2 && data->align != 4)
    {
        ParseError("byte_extract rule option has an invalid argument "
            "to 'align'. Valid arguments are '2' and '4'.");
        return false;
    }

    if (data->offset < 0 && data->relative_flag == 0)
    {
        ParseError("byte_extract rule option has a negative offset, but does "
            "not use the 'relative' option.");
        return false;
    }

    if (!data->name)
    {
        ParseError("byte_extract rule option must include variable name.");
        return false;
    }

    if (isdigit(data->name[0]))
    {
        ParseError("byte_extract rule option has a name which starts with a digit. "
            "Variable names must start with a letter.");
        return false;
    }

    if (data->base && !data->data_string_convert_flag)
    {
        ParseError("byte_extract rule option has a string conversion type "
            "(dec, hex, or oct) without the \"string\" "
            "argument.");
        return false;
    }

    if (numBytesInBitmask(data->bitmask_val) > data->bytes_to_grab)
    {
        ParseError("Number of bytes in \"bitmask\" value is greater than bytes to extract.");
        return false;
    }

    return true;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~count", Parameter::PT_INT, "1:10", nullptr,
      "number of bytes to pick up from the buffer" },

    { "~offset", Parameter::PT_INT, "-65535:65535", nullptr,
      "number of bytes into the buffer to start processing" },

    { "~name", Parameter::PT_STRING, nullptr, nullptr,
      "name of the variable that will be used in other rule options" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "offset from cursor instead of start of buffer" },

    { "multiplier", Parameter::PT_INT, "1:65535", "1",
      "scale extracted value by given amount" },

    { "align", Parameter::PT_INT, "0:4", "0",
      "round the number of converted bytes up to the next 2- or 4-byte boundary" },

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
      "applies as an AND to the extracted value before storage in 'name'" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ExtractModule : public Module
{
public:
    ExtractModule() : Module(s_name, s_help, s_params) { data.multiplier = 1; }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &byteExtractPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    ByteExtractData data = {};
};

bool ExtractModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    data.multiplier = 1;
    return true;
}

bool ExtractModule::end(const char*, int, SnortConfig*)
{
    if ( !data.endianness )
        data.endianness = ENDIAN_BIG;
    return ByteExtractVerify(&data);
}

bool ExtractModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~count") )
        data.bytes_to_grab = v.get_uint8();

    else if ( v.is("~offset") )
        data.offset = v.get_int32();

    else if ( v.is("~name") )
        data.name = snort_strdup(v.get_string());

    else if ( v.is("relative") )
        data.relative_flag = 1;

    else if ( v.is("align") )
        data.align = v.get_uint8();

    else if ( v.is("multiplier") )
        data.multiplier = v.get_uint16();

    else if ( v.is("big") )
        set_byte_order(data.endianness, ENDIAN_BIG, "byte_extract");

    else if ( v.is("little") )
        set_byte_order(data.endianness, ENDIAN_LITTLE, "byte_extract");

    else if ( v.is("dce") )
        set_byte_order(data.endianness, ENDIAN_FUNC, "byte_extract");

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
    return new ExtractModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* byte_extract_ctor(Module* p, OptTreeNode*)
{
    ExtractModule* m = (ExtractModule*)p;
    ByteExtractData& data = m->data;

    data.var_number = AddVarNameToList(data.name);

    if (data.var_number == IPS_OPTIONS_NO_VAR)
    {
        ParseError("Rule has more than %d variables.",
            NUM_IPS_OPTIONS_VARS);
        return nullptr;
    }
    return new ByteExtractOption(data);
}

static void byte_extract_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi byte_extract_api =
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
    nullptr,  // tinit
    nullptr,  // tterm
    byte_extract_ctor,
    byte_extract_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_byte_extract[] =
#endif
{
    &byte_extract_api.base,
    nullptr
};

//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------
#ifdef UNIT_TEST

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------
class ByteExtractDataMatcher
    : public Catch::Matchers::Impl::MatcherBase<ByteExtractData>
{
   public:
    ByteExtractDataMatcher(const ByteExtractData& value) : m_value(value) {}

    bool match(ByteExtractData const& rhs) const override
    {
        return ((m_value.bytes_to_grab == rhs.bytes_to_grab) &&
                (m_value.offset == rhs.offset) &&
                (m_value.relative_flag == rhs.relative_flag) &&
                (m_value.data_string_convert_flag == rhs.data_string_convert_flag) &&
                (m_value.align == rhs.align) &&
                (m_value.endianness == rhs.endianness) &&
                (m_value.base == rhs.base) &&
                (m_value.multiplier == rhs.multiplier) &&
                (m_value.var_number == rhs.var_number) &&
                (m_value.bitmask_val == rhs.bitmask_val));
    }

    std::string describe() const override
    {
        std::ostringstream ss;
        ss << "settings is equals to:\n";
        ss << "bytes_to_grab : " << m_value.bytes_to_grab << ";\n";
        ss << "offset : " << m_value.offset << ";\n";
        ss << "relative_flag : " << m_value.relative_flag << ";\n";
        ss << "data_string_convert_flag : " << m_value.data_string_convert_flag << ";\n";
        ss << "align : " << m_value.align << ";\n";
        ss << "endianness : " << m_value.endianness << ";\n";
        ss << "base : " << m_value.base << ";\n";
        ss << "multiplier : " << m_value.multiplier << ";\n";
        ss << "bitmask_val : " << m_value.bitmask_val << ";\n";
        ss << "var_number : " << m_value.var_number << ";\n";
        return ss.str();
    }

   private:
    ByteExtractData m_value;
};

ByteExtractDataMatcher ByteExtractDataEquals(const ByteExtractData& value)
{
    return {value};
}

class SetBufferOptionHelper : public IpsOption
{
   public:
    SetBufferOptionHelper(const char* value)
        : IpsOption(value, RULE_OPTION_TYPE_BUFFER_SET)
    {
    }
};

//-------------------------------------------------------------------------
// option tests
//-------------------------------------------------------------------------

TEST_CASE("ByteExtractOption::operator== valid", "[byte_extract_tests]")
{
    SetBufferOptionHelper set_buf("test");

    char* lhs_name = new char[9];
    strcpy(lhs_name, "test_lhs");
    ByteExtractData data_lhs = {0, 0, 0, 0, 0, 0, 8, 1, 0, 0, lhs_name};
    ByteExtractOption lhs(data_lhs);

    char* rhs_name = new char[9];
    strcpy(rhs_name, "test_rhs");
    ByteExtractData data_rhs = {0, 0, 0, 0, 0, 0, 8, 1, 0, 0, rhs_name};
    ByteExtractOption rhs(data_rhs);

    CHECK(lhs == lhs);
    CHECK(lhs == rhs);
    CHECK(rhs == lhs);
}

TEST_CASE("ByteExtractOption::operator== invalid", "[byte_extract_tests]")
{
    SetBufferOptionHelper set_buf("test");

    char* lhs_name = new char[5];
    strcpy(lhs_name, "test");
    ByteExtractData data_lhs = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    ByteExtractOption lhs = (data_lhs);

    SECTION("not equal to IpsOption object") { CHECK(!(lhs == set_buf)); }
    SECTION("all fields is differ")
    {
        ByteExtractData data_rhs = {1, 4, true, false, 2, ENDIAN_FUNC,
            0, 1, 0x1, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("bytes_to_grab is differ")
    {
        ByteExtractData data_rhs = {1, 0, 0, 0, 0, 0, 0, 1, 0, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("offset is differ")
    {
        ByteExtractData data_rhs = {0, 1, 0, 0, 0, 0, 0, 1, 0, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("relative_flag is differ")
    {
        ByteExtractData data_rhs = {0, 0, true, 0, 0, 0, 0, 1, 0, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("data_string_convert_flag is differ")
    {
        ByteExtractData data_rhs = {0, 0, 0, true, 0, 0, 0, 1, 0, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("align is differ")
    {
        ByteExtractData data_rhs = {0, 0, 0, 0, 2, 0, 0, 1, 0, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("endianness is differ")
    {
        ByteExtractData data_rhs = {0, 0, 0, 0, 0, ENDIAN_FUNC,
            0, 1, 0, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("base is differ")
    {
        ByteExtractData data_rhs = {0, 0, 0, 0, 0, 0, 16, 1, 0, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("multiplier is differ")
    {
        ByteExtractData data_rhs = {0, 0, 0, 0, 0, 0, 0, 3, 0, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("bitmask is differ")
    {
        ByteExtractData data_rhs = {0, 0, 0, 0, 0, 0,
            0, 1, 0xFFFF, 0, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("var_number is differ")
    {
        ByteExtractData data_rhs = {0, 0, 0, 0, 0, 0, 0, 1, 0, 3, lhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("name is differ")
    {
        char* rhs_name = new char[5];
        strcpy(rhs_name, "tset");
        ByteExtractData data_rhs = {0, 0, 0, 0, 0, 0, 0, 1, 0, 3, rhs_name};
        ByteExtractOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
}

TEST_CASE("ByteExtractOption::hash", "[byte_extract_tests]")
{
    SetBufferOptionHelper set_buf("test");

    ByteExtractData data_lhs = {0, 0, 0, 0, 0, 0, 8, 1, 0, 0};
    ByteExtractOption lhs(data_lhs);

    SECTION("hash codes of any two equal objects are equal")
    {
        ByteExtractData data_rhs = {0, 0, 0, 0, 0, 0, 8, 1, 0, 0};
        ByteExtractOption rhs = (data_rhs);

        CHECK(lhs.hash() == lhs.hash());
        CHECK(lhs.hash() == rhs.hash());
    }
}

TEST_CASE("ByteExtractOption::eval valid", "[byte_extract_tests]")
{
    Packet p;
    p.data = (const uint8_t*)"Lorem 12345";
    p.dsize = 11;
    Cursor c(&p);

    for (unsigned i = 0; i < NUM_IPS_OPTIONS_VARS; ++i)
    {
        SetVarValueByIndex(0, i);
    }
    ClearIpsOptionsVars();

    char* name = new char[5];
    strcpy(name, "test");

    SECTION("1 byte read, all off")
    {
        ByteExtractData data = {1, 0, 0, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 76);
        CHECK(c.get_pos() == 1);
    }
    SECTION("1 byte read, offset 3")
    {
        ByteExtractData data = {1, 3, 0, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 101);
        CHECK(c.get_pos() == 4);
    }
    SECTION("1 byte read, offset 3, relative, cursor 3")
    {
        ByteExtractData data = {1, 3, 1, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        c.set_pos(3);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 49);
        CHECK(c.get_pos() == 7);
    }
    SECTION("1 byte read, offset -3, relative, cursor 3")
    {
        ByteExtractData data = {1, -3, 1, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        c.set_pos(3);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 76);
        CHECK(c.get_pos() == 1);
    }
    SECTION("1 byte read, offset 6, string conv, base 10")
    {
        ByteExtractData data = {1, 6, 0, 1, 0, ENDIAN_BIG, 10, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 1);
        CHECK(c.get_pos() == 7);
    }
    SECTION("1 byte read, offset 6, string conv, base 10, align 2")
    {
        ByteExtractData data = {1, 6, 0, 1, 2, ENDIAN_BIG, 10, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 2);
        CHECK(c.get_pos() == 7);
    }
    SECTION("3 byte read, offset 6, string conv, base 10, align 4")
    {
        ByteExtractData data = {3, 6, 0, 1, 4, ENDIAN_BIG, 10, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 124);
        CHECK(c.get_pos() == 9);
    }
    SECTION("1 byte read, offset 1, no string conv, align 2, mult 3")
    {
        ByteExtractData data = {1, 1, 0, 0, 2, ENDIAN_BIG, 0, 3, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 334);
        CHECK(c.get_pos() == 2);
    }
    SECTION("1 byte read, offset 3, no string conv, align 4, mult 5")
    {
        ByteExtractData data = {1, 3, 0, 0, 4, ENDIAN_BIG, 0, 5, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 508);
        CHECK(c.get_pos() == 4);
    }
    SECTION("1 byte read, offset 6, string conv, base 10, mult 7")
    {
        ByteExtractData data = {1, 6, 0, 1, 0, ENDIAN_BIG, 10, 7, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 7);
        CHECK(c.get_pos() == 7);
    }
    SECTION("2 byte read, bitmask 1100110011100011")
    {
        ByteExtractData data = {2, 0, 0, 0, 0, ENDIAN_BIG, 0, 1, 52451, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 19555);
        CHECK(c.get_pos() == 2);
    }
    SECTION("2 byte read, bitmask 1100110011100000")
    {
        ByteExtractData data = {2, 0, 0, 0, 0, ENDIAN_BIG, 0, 1, 52448, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 611);
        CHECK(c.get_pos() == 2);
    }
    SECTION("4 bytes read, ENDIAN_LITTLE")
    {
        ByteExtractData data = {4, 0, 0, 0, 0, ENDIAN_LITTLE, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 1701998412);
        CHECK(c.get_pos() == 4);
    }
    SECTION(
        "4 bytes read, ENDIAN_FUNC, packet.endianness = "
        "DCERPC_BO_FLAG__LITTLE_ENDIAN")
    {
        DceEndianness* auto_endian = new DceEndianness();
        auto_endian->hdr_byte_order = DCERPC_BO_FLAG__LITTLE_ENDIAN;
        auto_endian->data_byte_order = DCERPC_BO_FLAG__LITTLE_ENDIAN;
        p.endianness = auto_endian;
        ByteExtractData data = {4, 0, 0, 0, 0, ENDIAN_FUNC, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 1701998412);
        CHECK(c.get_pos() == 4);
    }
}

TEST_CASE("ByteExtractOption::eval invalid", "[byte_extract_tests]")
{
    Packet p;
    p.data = (const uint8_t*)"Lorem 9876";
    p.dsize = 11;
    Cursor c(&p);

    for (unsigned i = 0; i < NUM_IPS_OPTIONS_VARS; ++i)
    {
        SetVarValueByIndex(0, i);
    }
    ClearIpsOptionsVars();

    char* name = new char[5];
    strcpy(name, "test");

    SECTION("packet = nullptr")
    {
        ByteExtractData data = {1, 6, 0, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, nullptr) == IpsOption::NO_MATCH);
    }
    SECTION("read more than 4 bytes")
    {
        ByteExtractData data = {6, 0, 0, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
        CHECK(c.get_pos() == 0);
    }
    SECTION("check bounds of packet, offset > packet size")
    {
        ByteExtractData data = {1, 20, 0, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
        CHECK(c.get_pos() == 0);
    }
    SECTION("negative offset, without relative flag")
    {
        ByteExtractData data = {1, -20, 0, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
        CHECK(c.get_pos() == 0);
    }
    SECTION("negative offset, out of bounds")
    {
        ByteExtractData data = {1, -20, 1, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
        CHECK(c.get_pos() == 0);
    }
    SECTION("check bounds of packet, read 2 bytes, empty packet")
    {
        p.data = (const uint8_t*)"";
        p.dsize = 0;
        Cursor c2(&p);
        ByteExtractData data = {2, 0, 0, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c2, &p) == IpsOption::NO_MATCH);
        CHECK(c2.get_pos() == 0);
    }
    SECTION("align value to 1")
    {
        ByteExtractData data = {1, 0, 0, 0, 1, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 76);
        CHECK(c.get_pos() == 1);
    }
    SECTION("align value to 6")
    {
        ByteExtractData data = {1, 0, 0, 0, 6, ENDIAN_BIG, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 76);
        CHECK(c.get_pos() == 1);
    }
    SECTION("ENDIAN_FUNC, without definition of endianness in packet")
    {
        ByteExtractData data = {3, 0, 0, 0, 0, ENDIAN_FUNC, 0, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
        CHECK(c.get_pos() == 0);
    }
    SECTION("conversion from string, decimal number, base = 8")
    {
        ByteExtractData data = {3, 6, 0, 1, 0, ENDIAN_BIG, 8, 1, 0, 0, name};
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
        CHECK(c.get_pos() == 0);
    }
}

//-------------------------------------------------------------------------
// module tests
//-------------------------------------------------------------------------

TEST_CASE("ExtractModule lifecycle", "[byte_extract_tests]")
{
    ExtractModule obj;

    SECTION("test of constructor") { CHECK(obj.data.multiplier == 1); }
    SECTION("test of \"begin\" method")
    {
        CHECK(obj.begin(nullptr, 0, nullptr));
        ByteExtractData expected = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};

        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("test of \"end\" method")
    {
        obj.begin(nullptr, 0, nullptr);

        Value v_name("test");
        Parameter p_name = {
            "~name", Parameter::PT_STRING, nullptr, nullptr,
            "name of the variable that will be used in other rule options"};
        v_name.set(&p_name);
        obj.set(nullptr, v_name, nullptr);

        Value v_bytes(4.0);
        Parameter p_bytes = {"~count", Parameter::PT_INT, "1:10", nullptr,
            "number of bytes to pick up from the buffer"};
        v_bytes.set(&p_bytes);
        obj.set(nullptr, v_bytes, nullptr);

        CHECK(obj.end(nullptr, 0, nullptr));

        char* name = new char[5];
        strcpy(name, "test");
        ByteExtractData expected = {4, 0, 0, 0, 0, ENDIAN_BIG,
            0, 1, 0, 0, name};

        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));

        delete name;
    }
}

TEST_CASE("Test of byte_extract_ctor", "[byte_extract_tests]")
{
    ClearIpsOptionsVars();

    std::string name = "test";
    for (unsigned i = 0; i <= NUM_IPS_OPTIONS_VARS; ++i)
    {
        ExtractModule obj;
        obj.begin(nullptr, 0, nullptr);
        Value v((name + std::to_string(i)).c_str());
        Parameter p = {"~name", Parameter::PT_STRING, nullptr, nullptr,
            "name of the variable that will be used in other rule options"};
        v.set(&p);
        obj.set(nullptr, v, nullptr);
        if (i < NUM_IPS_OPTIONS_VARS)
        {
            IpsOption* res = byte_extract_ctor(&obj, nullptr);
            delete res;
        }
        else
        {
            IpsOption* res_null = byte_extract_ctor(&obj, nullptr);
            CHECK(res_null == nullptr);
        }
    }
}

TEST_CASE("ExtractModule::set", "[byte_extract_tests]")
{
    ExtractModule obj;
    obj.begin(nullptr, 0, nullptr);

    SECTION("set bytes_to_grab")
    {
        Value v(4.0);
        Parameter p = {"~count", Parameter::PT_INT, "1:10", nullptr,
            "number of bytes to pick up from the buffer"};
        v.set(&p);
        ByteExtractData expected = {4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set offset")
    {
        Value v(7.0);
        Parameter p = {"~offset", Parameter::PT_INT, "-65535:65535", nullptr,
            "number of bytes into the buffer to start processing"};
        v.set(&p);
        ByteExtractData expected = {0, 7, 0, 0, 0, 0, 0, 1, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set name")
    {
        Value v("test_name");
        Parameter p = {"~name", Parameter::PT_STRING, nullptr, nullptr,
            "name of the variable that will be used in other rule options"};
        v.set(&p);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data.name, Catch::Matchers::Equals("test_name"));
    }
    SECTION("set relative")
    {
        Value v(true);
        Parameter p = {"relative", Parameter::PT_IMPLIED, nullptr, nullptr,
            "offset from cursor instead of start of buffer"};
        v.set(&p);
        obj.set(nullptr, v, nullptr);
        ByteExtractData expected = {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set multiplier")
    {
        Value v(6.0);
        Parameter p = {"multiplier", Parameter::PT_INT, "1:65535", "1",
            "scale extracted value by given amount"};
        v.set(&p);
        ByteExtractData expected = {0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set align")
    {
        Value v(2.0);
        Parameter p = {"align", Parameter::PT_INT, "0:4", "0",
            "round the number of converted bytes up to the next 2- "
            "or 4-byte boundary"};
        v.set(&p);
        ByteExtractData expected = {0, 0, 0, 0, 2, 0, 0, 1, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set endianness")
    {
        Value v_big((double)ENDIAN_BIG);
        Parameter p_big = {"big", Parameter::PT_IMPLIED, nullptr, nullptr,
            "big endian"};
        v_big.set(&p_big);
        obj.set(nullptr, v_big, nullptr);
        ByteExtractData expected_big = {0, 0, 0, 0, 0, ENDIAN_BIG,
            0, 1, 0, 0, 0};
        CHECK(obj.set(nullptr, v_big, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected_big));

        Value v_lit((double)ENDIAN_LITTLE);
        Parameter p_lit = {"little", Parameter::PT_IMPLIED, nullptr, nullptr,
            "little endian"};
        v_lit.set(&p_lit);
        ByteExtractData expected_lit = {0, 0, 0, 0, 0, ENDIAN_LITTLE,
            0, 1, 0, 0, 0};
        CHECK(obj.set(nullptr, v_lit, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected_lit));

        Value v_dce((double)ENDIAN_FUNC);
        Parameter p_dce = {"dce", Parameter::PT_IMPLIED, nullptr, nullptr,
            "dcerpc2 determines endianness"};
        v_dce.set(&p_dce);
        ByteExtractData expected_dce = {0, 0, 0, 0, 0, ENDIAN_FUNC,
            0, 1, 0, 0, 0};
        CHECK(obj.set(nullptr, v_dce, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected_dce));
    }
    SECTION("set string")
    {
        Value v(true);
        Parameter p = {"string", Parameter::PT_IMPLIED, nullptr, nullptr,
            "convert from string"};
        v.set(&p);
        ByteExtractData expected = {0, 0, 0, 1, 0, 0, 10, 1, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set hex")
    {
        Value v(true);
        Parameter p = {"hex", Parameter::PT_IMPLIED, nullptr, nullptr,
            "convert from hex string"};
        v.set(&p);
        ByteExtractData expected = {0, 0, 0, 0, 0, 0, 16, 1, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set oct")
    {
        Value v(true);
        Parameter p = {"oct", Parameter::PT_IMPLIED, nullptr, nullptr,
            "convert from octal string"};
        v.set(&p);
        ByteExtractData expected = {0, 0, 0, 0, 0, 0, 8, 1, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set dec")
    {
        Value v(true);
        Parameter p = {"dec", Parameter::PT_IMPLIED, nullptr, nullptr,
            "convert from decimal string"};
        v.set(&p);
        ByteExtractData expected = {0, 0, 0, 0, 0, 0, 10, 1, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set bitmask")
    {
        Value v(1023.0);
        Parameter p = {"bitmask", Parameter::PT_INT, "0x1:0xFFFFFFFF", nullptr,
            "applies as an AND to the extracted value before "
            "storage in 'name'"};
        v.set(&p);
        ByteExtractData expected = {0, 0, 0, 0, 0, 0, 0, 1, 1023, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("invalid set")
    {
        Value v(1023.0);
        Parameter p = {"error", Parameter::PT_INT, "nan", nullptr,
            "not an option"};
        v.set(&p);
        ByteExtractData expected = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};

        CHECK(!obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
}

//-------------------------------------------------------------------------
// api tests
//-------------------------------------------------------------------------

TEST_CASE("ByteExtractVerify_valid", "[byte_extract_tests]")
{
    ByteExtractData obj;
    char* name = new char[5];
    strcpy(name, "test");

    SECTION("Minimum values, no string convertion")
    {
        obj = {1, -65535, 1, 0, 0, ENDIAN_FUNC, 0, 1, 0x1, 0, name};
        CHECK(ByteExtractVerify(&obj));
    }
    SECTION("Maximum values, no string convertion")
    {
        obj = {MAX_BYTES_TO_GRAB, 65535, 1, 0, 4, ENDIAN_FUNC, 0, 65535,
            0xFFFFFFFF, 0, name};
        CHECK(ByteExtractVerify(&obj));
    }

    SECTION("Minimum values, with string convertion")
    {
        obj = {1, -65535, 1, 1, 0, ENDIAN_FUNC, 8, 1, 0x1, 0, name};
        CHECK(ByteExtractVerify(&obj));
    }
    SECTION("Maximum values, with string convertion")
    {
        obj = {PARSELEN, 65535, 1, 1, 4, ENDIAN_FUNC,
            16, 65535, 0xFFFFFFFF, 0, name};
        CHECK(ByteExtractVerify(&obj));
    }
    delete name;
}

TEST_CASE("ByteExtractVerify_invalid", "[byte_extract_tests]")
{
    char* name = new char[5];
    strcpy(name, "test");
    ByteExtractData obj = {2, 7, 0, 0, 2, ENDIAN_FUNC, 0, 1, 0, 0, name};

    SECTION("bytes_to_grab checks")
    {
        obj.bytes_to_grab = MAX_BYTES_TO_GRAB + 1;
        CHECK((!ByteExtractVerify(&obj)));

        obj.data_string_convert_flag = true;
        obj.bytes_to_grab = PARSELEN + 1;
        CHECK((!ByteExtractVerify(&obj)));
    }
    SECTION("align checks")
    {
        obj.align = 1;
        CHECK((!ByteExtractVerify(&obj)));

        obj.align = 6;
        CHECK((!ByteExtractVerify(&obj)));
    }
    SECTION("offset checks")
    {
        obj.offset = -5;
        CHECK((!ByteExtractVerify(&obj)));
    }
    SECTION("name checks")
    {
        delete name;
        obj.name = nullptr;
        CHECK((!ByteExtractVerify(&obj)));

        name = new char[6];
        strcpy(name, "9test");
        obj.name = name;
        CHECK((!ByteExtractVerify(&obj)));
    }
    SECTION("base checks")
    {
        obj.base = 16;
        CHECK((!ByteExtractVerify(&obj)));
    }
    SECTION("bitmask checks")
    {
        obj.bytes_to_grab = 2;
        obj.bitmask_val = 1048575;
        CHECK((!ByteExtractVerify(&obj)));
    }
    delete name;
}

#endif