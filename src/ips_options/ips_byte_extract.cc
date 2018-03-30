//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "utils/util.h"

#include "extract.h"

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
    uint32_t a,b,c;
    const ByteExtractData* data = &config;

    a = data->bytes_to_grab;
    b = data->offset;
    c = data->base;

    mix(a,b,c);

    a += (data->relative_flag << 24 |
        data->data_string_convert_flag << 16 |
        data->align << 8 |
        data->endianness);
    b += data->multiplier;
    c += data->var_number;

    mix(a,b,c);

    a += data->bitmask_val;
    mix_str(a,b,c,get_name());

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
    Profile profile(byteExtractPerfStats);

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
    ExtractModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &byteExtractPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    ByteExtractData data;
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
        data.bytes_to_grab = v.get_long();

    else if ( v.is("~offset") )
        data.offset = v.get_long();

    else if ( v.is("~name") )
        data.name = snort_strdup(v.get_string());

    else if ( v.is("relative") )
        data.relative_flag = 1;

    else if ( v.is("align") )
        data.align = v.get_long();

    else if ( v.is("multiplier") )
        data.multiplier = v.get_long();

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
