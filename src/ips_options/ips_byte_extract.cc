//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "utils/util.h"

#include "extract.h"

#ifdef UNIT_TEST
#include <catch/snort_catch.h>
#include "service_inspectors/dce_rpc/dce_common.h"
#endif

using namespace snort;

static THREAD_LOCAL ProfileStats byteExtractPerfStats;

#define s_name "byte_extract"

#define s_help \
    "rule option to convert data to an integer variable"

struct ByteExtractData : public ByteData
{
    uint32_t multiplier;
    uint8_t align;
    int8_t var_number;
    char* name;
};

class ByteExtractOption : public IpsOption
{
public:
    ByteExtractOption(const ByteExtractData& c) :
        IpsOption(s_name), config(c)
    { }

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
    void apply_alignment(uint32_t& value);
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteExtractOption::hash() const
{
    uint32_t a = config.bytes_to_extract;
    uint32_t b = config.offset;
    uint32_t c = config.base;

    mix(a,b,c);

    a += (config.relative_flag << 24 |
        config.string_convert_flag << 16 |
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
    if (!IpsOption::operator==(ips))
        return false;

    const ByteExtractOption& rhs = (const ByteExtractOption&)ips;
    const ByteExtractData* left = &config;
    const ByteExtractData* right = &rhs.config;

    if ((left->bytes_to_extract == right->bytes_to_extract) and
        (left->offset == right->offset) and
        (left->relative_flag == right->relative_flag) and
        (left->string_convert_flag == right->string_convert_flag) and
        (left->align == right->align) and
        (left->endianness == right->endianness) and
        (left->base == right->base) and
        (left->multiplier == right->multiplier) and
        (left->var_number == right->var_number) and
        (left->bitmask_val == right->bitmask_val))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus ByteExtractOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(byteExtractPerfStats);

    uint32_t value = 0;
    int bytes_read = extract_data(config, c, p, value);

    if (bytes_read == NO_MATCH)
        return NO_MATCH;

    value *= config.multiplier;

    apply_alignment(value);

    SetVarValueByIndex(value, config.var_number);

    c.add_pos(config.offset + bytes_read);

    return MATCH;
}

void ByteExtractOption::apply_alignment(uint32_t& value)
{
    if ((config.align == 4) and (value % 4))
    {
        value = value + 4 - (value % 4);
    }
    else if ((config.align == 2) and (value % 2))
    {
        value = value + 2 - (value % 2);
    }
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

/* Checks a ByteExtractData instance for errors. */
static bool ByteExtractVerify(ByteExtractData* data)
{
    if (data->bytes_to_extract > MAX_BYTES_TO_GRAB and data->string_convert_flag == 0)
    {
        ParseError("byte_extract rule option cannot extract more than %d bytes.",
            MAX_BYTES_TO_GRAB);
        return false;
    }

    if (data->bytes_to_extract > PARSELEN and data->string_convert_flag == 1)
    {
        ParseError("byte_extract rule cannot process more than %d bytes for "
            "string extraction.",  PARSELEN);
        return false;
    }

    if (data->align != 0 and data->align != 2 and data->align != 4)
    {
        ParseError("byte_extract rule option has an invalid argument "
            "to 'align'. Valid arguments are '2' and '4'.");
        return false;
    }

    if (data->offset < 0 and data->relative_flag == 0)
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

    if (data->base and !data->string_convert_flag)
    {
        ParseError("byte_extract rule option has a string conversion type "
            "(dec, hex, or oct) without the \"string\" "
            "argument.");
        return false;
    }

    if (numBytesInBitmask(data->bitmask_val) > data->bytes_to_extract)
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
      "number of bytes to pick up from the buffer (string can pick less)" },

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
    ByteExtractData data{};
};

bool ExtractModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    data.multiplier = 1;
    return true;
}

bool ExtractModule::end(const char*, int, SnortConfig*)
{
    if (!data.endianness)
        data.endianness = ENDIAN_BIG;
    return ByteExtractVerify(&data);
}

bool ExtractModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("~count"))
        data.bytes_to_extract = v.get_uint8();

    else if (v.is("~offset"))
        data.offset = v.get_int32();

    else if (v.is("~name"))
        data.name = snort_strdup(v.get_string());

    else if (v.is("relative"))
        data.relative_flag = 1;

    else if (v.is("align"))
        data.align = v.get_uint8();

    else if (v.is("multiplier"))
        data.multiplier = v.get_uint16();

    else if (v.is("big"))
        set_byte_order(data.endianness, ENDIAN_BIG, "byte_extract");

    else if (v.is("little"))
        set_byte_order(data.endianness, ENDIAN_LITTLE, "byte_extract");

    else if (v.is("dce"))
        set_byte_order(data.endianness, ENDIAN_FUNC, "byte_extract");

    else if (v.is("string"))
    {
        data.string_convert_flag = 1;
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
#define INITIALIZE(obj, bytes_to_extract_value, offset_value, relative_flag_value, \
    string_convert_flag_value, align_value, endianness_value, base_value,\
    multiplier_value, bitmask_val_value, var_number_value, name_value) \
    obj.base = base_value; \
    obj.bitmask_val = bitmask_val_value; \
    obj.bytes_to_extract = bytes_to_extract_value; \
    obj.offset = offset_value; \
    obj.endianness = endianness_value; \
    obj.relative_flag = relative_flag_value; \
    obj.string_convert_flag = string_convert_flag_value; \
    obj.multiplier = multiplier_value; \
    obj.align = align_value; \
    obj.var_number = var_number_value; \
    obj.name = name_value

class ByteExtractDataMatcher
    : public Catch::Matchers::Impl::MatcherBase<ByteExtractData>
{
public:
    ByteExtractDataMatcher(const ByteExtractData& value) : m_value(value) {}

    bool match(ByteExtractData const& rhs) const override
    {
        return ((m_value.bytes_to_extract == rhs.bytes_to_extract) and
            (m_value.offset == rhs.offset) and
            (m_value.relative_flag == rhs.relative_flag) and
            (m_value.string_convert_flag == rhs.string_convert_flag) and
            (m_value.align == rhs.align) and
            (m_value.endianness == rhs.endianness) and
            (m_value.base == rhs.base) and
            (m_value.multiplier == rhs.multiplier) and
            (m_value.var_number == rhs.var_number) and
            (m_value.bitmask_val == rhs.bitmask_val));
    }

    std::string describe() const override
    {
        std::ostringstream ss;
        ss << "settings is equals to:\n";
        ss << "bytes_to_extract : " << m_value.bytes_to_extract << ";\n";
        ss << "offset : " << m_value.offset << ";\n";
        ss << "relative_flag : " << m_value.relative_flag << ";\n";
        ss << "string_convert_flag : " << m_value.string_convert_flag << ";\n";
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

static ByteExtractDataMatcher ByteExtractDataEquals(const ByteExtractData& value)
{
    return {value};
}

//-------------------------------------------------------------------------
// option tests
//-------------------------------------------------------------------------

TEST_CASE("ByteExtractOption::operator== valid", "[ips_byte_extract]")
{
    char* lhs_name = new char[9];
    strcpy(lhs_name, "test_lhs");
    ByteExtractData data_lhs;
    INITIALIZE(data_lhs, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, lhs_name);
    ByteExtractOption lhs(data_lhs);

    char* rhs_name = new char[9];
    strcpy(rhs_name, "test_rhs");
    ByteExtractData data_rhs;
    INITIALIZE(data_rhs, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, rhs_name);
    ByteExtractOption rhs(data_rhs);

    CHECK(lhs == rhs);
}

TEST_CASE("ByteExtractOption::operator== invalid", "[ips_byte_extract]")
{
    char* lhs_name = new char[5];
    strcpy(lhs_name, "test");
    ByteExtractData data_lhs;
    INITIALIZE(data_lhs, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, nullptr);
    ByteExtractOption lhs(data_lhs);

    SECTION("all fields is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 1, 4, true, false, 2, ENDIAN_FUNC, 0, 1, 0x1, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("bytes_to_extract is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("offset is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("relative_flag is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, true, 0, 0, 0, 0, 1, 0, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("string_convert_flag is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, 0, true, 0, 0, 0, 1, 0, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("align is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, 0, 0, 2, 0, 0, 1, 0, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("endianness is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, 0, 0, 0, ENDIAN_FUNC, 0, 1, 0, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("base is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, 0, 0, 0, 0, 16, 1, 0, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("multiplier is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("bitmask is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, 0, 0, 0, 0, 0, 1, 0xFFFF, 0, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("var_number is different")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3, lhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
    SECTION("name is different")
    {
        delete[] lhs_name;
        char* rhs_name = new char[5];
        strcpy(rhs_name, "unix");
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3, rhs_name);
        ByteExtractOption rhs(data_rhs);
        CHECK(lhs != rhs);
    }
}

TEST_CASE("ByteExtractOption::hash", "[ips_byte_extract]")
{
    ByteExtractData data_lhs;
    INITIALIZE(data_lhs, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, nullptr);
    ByteExtractOption lhs(data_lhs);

    SECTION("hash codes of any two equal objects are equal")
    {
        ByteExtractData data_rhs;
        INITIALIZE(data_rhs, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, nullptr);
        ByteExtractOption rhs(data_rhs);

        CHECK(lhs.hash() == rhs.hash());
    }
}

TEST_CASE("ByteExtractOption::eval valid", "[ips_byte_extract]")
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

    SECTION("1 byte read, offset 6, string conversion, base 10, align 2")
    {
        ByteExtractData data;
        INITIALIZE(data, 1, 6, 0, 1, 2, ENDIAN_BIG, 10, 1, 0, 0, name);
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 2);
        CHECK(c.get_pos() == 7);
    }
    SECTION("3 byte read, offset 6, string conversion, base 10, align 4")
    {
        ByteExtractData data;
        INITIALIZE(data, 3, 6, 0, 1, 4, ENDIAN_BIG, 10, 1, 0, 0, name);
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 124);
        CHECK(c.get_pos() == 9);
    }
    SECTION("1 byte read, offset 1, no string conversion, align 2, multiply 3")
    {
        ByteExtractData data;
        INITIALIZE(data, 1, 1, 0, 0, 2, ENDIAN_BIG, 0, 3, 0, 0, name);
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 334);
        CHECK(c.get_pos() == 2);
    }
    SECTION("1 byte read, offset 3, no string conversion, align 4, multiply 5")
    {
        ByteExtractData data;
        INITIALIZE(data, 1, 3, 0, 0, 4, ENDIAN_BIG, 0, 5, 0, 0, name);
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 508);
        CHECK(c.get_pos() == 4);
    }
    SECTION("bytes_to_extract bigger than amount of bytes left in the buffer")
    {
        ByteExtractData data;
        c.set_pos(9);
        INITIALIZE(data, 3, 0, 1, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name);
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("String truncation")
    {
        ByteExtractData data;
        c.set_pos(10);
        INITIALIZE(data, 2, 0, 1, 1, 0, ENDIAN_BIG, 10, 1, 0, 0, name);
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 5);
    }

    SECTION("Negative offset")
    {
        SECTION("Cursor on last byte of buffers")
        {
            ByteExtractData data;
            c.set_pos(11);
            INITIALIZE(data, 1, -6, 1, 0, 0, ENDIAN_BIG, 10, 1, 0, 0, name);
            ByteExtractOption opt(data);
            CHECK(opt.eval(c, &p) == IpsOption::MATCH);
            uint32_t res = 0;
            GetVarValueByIndex(&res, 0);
            CHECK(res == 32);
        }
        SECTION("Cursor on last byte of buffers, bytes_to_extract is bigger than offset")
        {
            ByteExtractData data;
            c.set_pos(11);
            INITIALIZE(data, 4, -3, 1, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name);
            ByteExtractOption opt(data);
            CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
        }
        SECTION("Cursor on the last byte of buffer with string flag")
        {
            ByteExtractData data;
            c.set_pos(11);
            INITIALIZE(data, 1, -2, 1, 1, 0, ENDIAN_BIG, 10, 1, 0, 0, name);
            ByteExtractOption opt(data);
            CHECK(opt.eval(c, &p) == IpsOption::MATCH);
            uint32_t res = 0;
            GetVarValueByIndex(&res, 0);
            CHECK(res == 4);
        }
        SECTION("String truncation")
        {
            ByteExtractData data;
            c.set_pos(11);
            INITIALIZE(data, 3, -2, 1, 1, 0, ENDIAN_BIG, 10, 1, 0, 0, name);
            ByteExtractOption opt(data);
            CHECK(opt.eval(c, &p) == IpsOption::MATCH);
            uint32_t res = 0;
            GetVarValueByIndex(&res, 0);
            CHECK(res == 45);
        }
    }
}

TEST_CASE("ByteExtractOption::eval invalid", "[ips_byte_extract]")
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

    SECTION("align value to 1")
    {
        ByteExtractData data;
        INITIALIZE(data, 1, 0, 0, 0, 1, ENDIAN_BIG, 0, 1, 0, 0, name);
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 76);
        CHECK(c.get_pos() == 1);
    }
    SECTION("align value to 6")
    {
        ByteExtractData data;
        INITIALIZE(data, 1, 0, 0, 0, 6, ENDIAN_BIG, 0, 1, 0, 0, name);
        ByteExtractOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 76);
        CHECK(c.get_pos() == 1);
    }
}

//-------------------------------------------------------------------------
// module tests
//-------------------------------------------------------------------------

TEST_CASE("ExtractModule lifecycle", "[ips_byte_extract]")
{
    ExtractModule obj;

    SECTION("test of constructor")
    {
        CHECK(obj.data.multiplier == 1);
    }
    SECTION("test of \"begin\" method")
    {
        CHECK(obj.begin(nullptr, 0, nullptr));
        ByteExtractData expected;
        INITIALIZE(expected, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, nullptr);

        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("test of \"end\" method")
    {
        obj.begin(nullptr, 0, nullptr);

        Value v_name("test");
        Parameter p_name{
            "~name", Parameter::PT_STRING, nullptr, nullptr,
            "name of the variable that will be used in other rule options"};
        v_name.set(&p_name);
        obj.set(nullptr, v_name, nullptr);

        Value v_bytes(4.0);
        Parameter p_bytes{
            "~count", Parameter::PT_INT, "1:10", nullptr,
            "number of bytes to pick up from the buffer"};
        v_bytes.set(&p_bytes);
        obj.set(nullptr, v_bytes, nullptr);

        CHECK(obj.end(nullptr, 0, nullptr));

        char* name = new char[5];
        strcpy(name, "test");
        ByteExtractData expected;
        INITIALIZE(expected, 4, 0, 0, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, name);

        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));

        delete[] name;
        delete[] obj.data.name;
    }
}

TEST_CASE("Test of byte_extract_ctor", "[ips_byte_extract]")
{
    ClearIpsOptionsVars();

    std::string name = "test";
    for (unsigned i = 0; i <= NUM_IPS_OPTIONS_VARS; ++i)
    {
        ExtractModule obj;
        obj.begin(nullptr, 0, nullptr);
        Value v((name + std::to_string(i)).c_str());
        Parameter p{
            "~name", Parameter::PT_STRING, nullptr, nullptr,
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
            delete[] obj.data.name;
        }
    }
}

TEST_CASE("ExtractModule::set", "[ips_byte_extract]")
{
    ExtractModule obj;
    obj.begin(nullptr, 0, nullptr);

    SECTION("set bytes_to_extract")
    {
        Value v(4.0);
        Parameter p{
            "~count", Parameter::PT_INT, "1:10", nullptr,
            "number of bytes to pick up from the buffer"};
        v.set(&p);
        ByteExtractData expected;
        INITIALIZE(expected, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set offset")
    {
        Value v(7.0);
        Parameter p{
            "~offset", Parameter::PT_INT, "-65535:65535", nullptr,
            "number of bytes into the buffer to start processing"};
        v.set(&p);
        ByteExtractData expected;
        INITIALIZE(expected, 0, 7, 0, 0, 0, 0, 0, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set name")
    {
        Value v("test_name");
        Parameter p{
            "~name", Parameter::PT_STRING, nullptr, nullptr,
            "name of the variable that will be used in other rule options"};
        v.set(&p);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data.name, Catch::Matchers::Equals("test_name"));
    }
    SECTION("set relative")
    {
        Value v(true);
        Parameter p{
            "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
            "offset from cursor instead of start of buffer"};
        v.set(&p);
        obj.set(nullptr, v, nullptr);
        ByteExtractData expected;
        INITIALIZE(expected, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set multiplier")
    {
        Value v(6.0);
        Parameter p{
            "multiplier", Parameter::PT_INT, "1:65535", "1",
            "scale extracted value by given amount"};
        v.set(&p);
        ByteExtractData expected;
        INITIALIZE(expected, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set align")
    {
        Value v(2.0);
        Parameter p{
            "align", Parameter::PT_INT, "0:4", "0",
            "round the number of converted bytes up to the next 2- "
            "or 4-byte boundary"};
        v.set(&p);
        ByteExtractData expected;
        INITIALIZE(expected, 0, 0, 0, 0, 2, 0, 0, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set endianness")
    {
        Value v_big((double)ENDIAN_BIG);
        Parameter p_big{"big", Parameter::PT_IMPLIED, nullptr, nullptr, "big endian"};
        v_big.set(&p_big);
        obj.set(nullptr, v_big, nullptr);
        ByteExtractData expected_big;
        INITIALIZE(expected_big, 0, 0, 0, 0, 0, ENDIAN_BIG, 0, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v_big, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected_big));

        Value v_lit((double)ENDIAN_LITTLE);
        Parameter p_lit{"little", Parameter::PT_IMPLIED, nullptr, nullptr, "little endian"};
        v_lit.set(&p_lit);
        ByteExtractData expected_lit;
        INITIALIZE(expected_lit, 0, 0, 0, 0, 0, ENDIAN_LITTLE, 0, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v_lit, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected_lit));

        Value v_dce((double)ENDIAN_FUNC);
        Parameter p_dce{"dce", Parameter::PT_IMPLIED, nullptr, nullptr,
            "dcerpc2 determines endianness"};
        v_dce.set(&p_dce);
        ByteExtractData expected_dce;
        INITIALIZE(expected_dce, 0, 0, 0, 0, 0, ENDIAN_FUNC, 0, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v_dce, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected_dce));
    }
    SECTION("set string")
    {
        Value v(true);
        Parameter p{
            "string", Parameter::PT_IMPLIED, nullptr, nullptr,
            "convert from string"};
        v.set(&p);
        ByteExtractData expected;
        INITIALIZE(expected, 0, 0, 0, 1, 0, 0, 10, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set hex")
    {
        Value v(true);
        Parameter p{
            "hex", Parameter::PT_IMPLIED, nullptr, nullptr,
            "convert from hex string"};
        v.set(&p);
        ByteExtractData expected;
        INITIALIZE(expected, 0, 0, 0, 0, 0, 0, 16, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set oct")
    {
        Value v(true);
        Parameter p{
            "oct", Parameter::PT_IMPLIED, nullptr, nullptr,
            "convert from octal string"};
        v.set(&p);
        ByteExtractData expected;
        INITIALIZE(expected, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set dec")
    {
        Value v(true);
        Parameter p{
            "dec", Parameter::PT_IMPLIED, nullptr, nullptr,
            "convert from decimal string"};
        v.set(&p);
        ByteExtractData expected;
        INITIALIZE(expected, 0, 0, 0, 0, 0, 0, 10, 1, 0, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    SECTION("set bitmask")
    {
        Value v(1023.0);
        Parameter p{
            "bitmask", Parameter::PT_INT, "0x1:0xFFFFFFFF", nullptr,
            "applies as an AND to the extracted value before "
            "storage in 'name'"};
        v.set(&p);
        ByteExtractData expected;
        INITIALIZE(expected, 0, 0, 0, 0, 0, 0, 0, 1, 1023, 0, nullptr);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteExtractDataEquals(expected));
    }
    delete[] obj.data.name;
}

//-------------------------------------------------------------------------
// api tests
//-------------------------------------------------------------------------

TEST_CASE("ByteExtractVerify_valid", "[ips_byte_extract]")
{
    ByteExtractData obj;
    char name[] = "test";

    SECTION("Minimum values, no string conversion")
    {
        INITIALIZE(obj, 1, -65535, 1, 0, 0, ENDIAN_FUNC, 0, 1, 0x1, 0, name);
        CHECK(ByteExtractVerify(&obj));
    }
    SECTION("Maximum values, no string conversion")
    {
        INITIALIZE(obj, MAX_BYTES_TO_GRAB, 65535, 1, 0, 4, ENDIAN_FUNC,
            0, 65535, 0xFFFFFFFF, 0, name);
        CHECK(ByteExtractVerify(&obj));
    }
    SECTION("Minimum values, with string conversion")
    {
        INITIALIZE(obj, 1, -65535, 1, 1, 0, ENDIAN_FUNC, 8, 1, 0x1, 0, name);
        CHECK(ByteExtractVerify(&obj));
    }
    SECTION("Maximum values, with string conversion")
    {
        INITIALIZE(obj, PARSELEN, 65535, 1, 1, 4, ENDIAN_FUNC, 16, 65535, 0xFFFFFFFF, 0, name);
        CHECK(ByteExtractVerify(&obj));
    }
}

TEST_CASE("ByteExtractVerify_invalid", "[ips_byte_extract]")
{
    char* name = new char[5];
    strcpy(name, "test");
    ByteExtractData obj;
    INITIALIZE(obj, 2, 7, 0, 0, 2, ENDIAN_FUNC, 0, 1, 0, 0, name);

    SECTION("bytes_to_extract checks")
    {
        obj.bytes_to_extract = MAX_BYTES_TO_GRAB + 1;
        CHECK((!ByteExtractVerify(&obj)));

        obj.string_convert_flag = true;
        obj.bytes_to_extract = PARSELEN + 1;
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
        delete[] name;
        obj.name = nullptr;
        CHECK((!ByteExtractVerify(&obj)));

        name = new char[6];
        strcpy(name, "64bit");
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
        obj.bytes_to_extract = 2;
        obj.bitmask_val = 1048575;
        CHECK((!ByteExtractVerify(&obj)));
    }
    delete[] name;
}

#endif
