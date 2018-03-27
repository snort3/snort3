//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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

/* ips_base64.cc */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_util.h"
#include "detection/treenodes.h"
#include "hash/hashfcn.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "log/messages.h"
#include "mime/decode_b64.h"
#include "profiler/profiler.h"
#include "utils/util_unfold.h"

using namespace snort;

struct Base64DecodeBuffer
{
    uint8_t data[DECODE_BLEN];
    uint32_t size;
};

static THREAD_LOCAL Base64DecodeBuffer* base64_decode_buffer;
static THREAD_LOCAL ProfileStats base64PerfStats;

#define s_name "base64_decode"

#define s_help \
    "rule option to decode base64 data - must be used with base64_data option"

//-------------------------------------------------------------------------
// base64_decode
//-------------------------------------------------------------------------

#define BASE64DECODE_RELATIVE_FLAG 0x01

struct Base64DecodeData
{
    uint32_t bytes_to_decode;
    uint32_t offset;
    uint8_t flags;
};

class Base64DecodeOption : public IpsOption
{
public:
    Base64DecodeOption(const Base64DecodeData& c) : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE)
    { config = c; }


    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    Base64DecodeData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t Base64DecodeOption::hash() const
{
    uint32_t a,b,c;

    a = config.bytes_to_decode;
    b = config.offset;
    c = config.flags;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    finalize(a,b,c);

    return c;
}

bool Base64DecodeOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const Base64DecodeOption& rhs = (const Base64DecodeOption&)ips;
    const Base64DecodeData* left = &config;
    const Base64DecodeData* right = &rhs.config;

    if ((left->bytes_to_decode == right->bytes_to_decode) &&
        ( left->offset == right->offset) &&
        ( left->flags == right->flags))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus Base64DecodeOption::eval(Cursor& c, Packet*)
{
    Profile profile(base64PerfStats);
    base64_decode_buffer->size = 0;

    Base64DecodeData* idx = (Base64DecodeData*)&config;
    const uint8_t* start_ptr = nullptr;
    unsigned size = 0;

    if (idx->flags & BASE64DECODE_RELATIVE_FLAG)
    {
        start_ptr = c.start();
        size = c.length();
    }
    else
    {
        start_ptr = c.buffer();
        size = c.size();
    }

    if ( idx->offset >= size )
        return NO_MATCH;

    start_ptr += idx->offset;
    size -= idx->offset;

    uint8_t base64_buf[DECODE_BLEN];
    uint32_t base64_size = 0;

    if (sf_unfold_header(start_ptr, size, base64_buf, sizeof(base64_buf), &base64_size, 0, nullptr) != 0)
        return NO_MATCH;

    if (idx->bytes_to_decode && (base64_size > idx->bytes_to_decode))
    {
        base64_size = idx->bytes_to_decode;
    }

    if (sf_base64decode(base64_buf, base64_size, base64_decode_buffer->data,
        sizeof(base64_decode_buffer->data), &base64_decode_buffer->size) != 0)
        return NO_MATCH;

    return MATCH;
}

//-------------------------------------------------------------------------
// decode module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "bytes", Parameter::PT_INT, "1:", nullptr,
      "number of base64 encoded bytes to decode" },

    { "offset", Parameter::PT_INT, "0:", "0",
      "bytes past start of buffer to start decoding" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "apply offset to cursor instead of start of buffer" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class B64DecodeModule : public Module
{
public:
    B64DecodeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &base64PerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    Base64DecodeData data;
};

bool B64DecodeModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool B64DecodeModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("bytes") )
        data.bytes_to_decode = v.get_long();

    else if ( v.is("offset") )
        data.offset = v.get_long();

    else if ( v.is("relative") )
        data.flags |= BASE64DECODE_RELATIVE_FLAG;

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new B64DecodeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* base64_decode_ctor(Module* p, OptTreeNode*)
{
    B64DecodeModule* m = (B64DecodeModule*)p;
    return new Base64DecodeOption(m->data);
}

static void base64_decode_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi base64_decode_api =
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
    1, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    base64_decode_ctor,
    base64_decode_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// base64_data
//-------------------------------------------------------------------------

#define s_data_name "base64_data"
#define s_data_help "set detection cursor to decoded Base64 data"

class Base64DataOption : public IpsOption
{
public:
    Base64DataOption() : IpsOption(s_data_name, RULE_OPTION_TYPE_BUFFER_SET) { }

    CursorActionType get_cursor_type() const override
    { return CAT_SET_OTHER; }

    EvalStatus eval(Cursor&, Packet*) override;
};

IpsOption::EvalStatus Base64DataOption::eval(Cursor& c, Packet*)
{
    Profile profile(base64PerfStats);

    if ( !base64_decode_buffer->size )
        return NO_MATCH;

    c.set(s_data_name, base64_decode_buffer->data, base64_decode_buffer->size);

    return MATCH;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static class IpsOption* base64_data_ctor(
    Module*, OptTreeNode* otn)
{
    if ( !otn_has_plugin(otn, "base64_decode") )
    {
        ParseError("base64_decode needs to be specified before base64_data in a rule");
        return nullptr;
    }

    return new Base64DataOption;
}

static void base64_data_dtor(IpsOption* p)
{
    delete p;
}

static void base64_data_tinit(SnortConfig*)
{
    base64_decode_buffer = new Base64DecodeBuffer();
}

static void base64_data_tterm(SnortConfig*)
{
    delete base64_decode_buffer;
    base64_decode_buffer = nullptr;
}

static const IpsApi base64_data_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_data_name,
        s_data_help,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    base64_data_tinit,
    base64_data_tterm,
    base64_data_ctor,
    base64_data_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_base64[] =
#endif
{
    &base64_decode_api.base,
    &base64_data_api.base,
    nullptr
};

