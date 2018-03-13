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

/*
**  @file        sp_asn1.c
**
**  @author      Daniel Roelker <droelker@sourcefire.com>
**
**  @brief       Decode and detect ASN.1 types, lengths, and data.
**
**  This detection plugin adds ASN.1 detection functions on a per rule
**  basis.  ASN.1 detection plugins can be added by editing this file and
**  providing an interface in the configuration code.
**
**  Detection Plugin Interface:
**
**  asn1: [detection function],[arguments],[offset type],[size]
**
**  Detection Functions:
**
**  bitstring_overflow: no arguments
**  double_overflow:    no arguments
**  oversize_length:    max size (if no max size, then just return value)
**
**  alert udp any any -> any 161 (msg:"foo"; \
**      asn1: oversize_length 10000, absolute_offset 0;)
**
**  alert tcp any any -> any 162 (msg:"foo2"; \
**      asn1: bitstring_overflow, oversize_length 500, relative_offset 7;)
**
**
**  Note that further general information about ASN.1 can be found in
**  the file doc/README.asn1.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "asn1_detect.h"
#include "asn1_util.h"

using namespace snort;

#define BITSTRING_OPT  "bitstring_overflow"
#define DOUBLE_OPT     "double_overflow"
#define PRINT_OPT      "print"

#define LENGTH_OPT     "oversize_length"
#define ABS_OFFSET_OPT "absolute_offset"
#define REL_OFFSET_OPT "relative_offset"

#define DELIMITERS " ,\t\n"

static THREAD_LOCAL ProfileStats asn1PerfStats;

#define s_name "asn1"

#define s_help \
    "rule option for asn1 detection"

class Asn1Option : public IpsOption
{
public:
    Asn1Option(ASN1_CTXT& c) : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_relative() override
    { return ( config.offset_type == REL_OFFSET ); }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    ASN1_CTXT config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t Asn1Option::hash() const
{
    uint32_t a,b,c;
    const ASN1_CTXT* data = &config;

    a = data->bs_overflow;
    b = data->double_overflow;
    c = data->print;

    mix(a,b,c);

    a += data->length;
    b += data->max_length;
    c += data->offset;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    a += data->offset_type;

    finalize(a,b,c);

    return c;
}

bool Asn1Option::operator==(const IpsOption& rhs) const
{
    if ( !IpsOption::operator==(rhs) )
        return false;

    const Asn1Option& asn1 = (const Asn1Option&)rhs;

    const ASN1_CTXT* left = &config;
    const ASN1_CTXT* right = &asn1.config;

    if ((left->bs_overflow == right->bs_overflow) &&
        (left->double_overflow == right->double_overflow) &&
        (left->print == right->print) &&
        (left->length == right->length) &&
        (left->max_length == right->max_length) &&
        (left->offset == right->offset) &&
        (left->offset_type == right->offset_type))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus Asn1Option::eval(Cursor& c, Packet* p)
{
    Profile profile(asn1PerfStats);

    //  Failed if there is no data to decode.
    if (!p->data)
        return NO_MATCH;

    if ( Asn1DoDetect(c.buffer(), c.size(), &config, c.start()) )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { BITSTRING_OPT, Parameter::PT_IMPLIED, nullptr, nullptr,
      "detects invalid bitstring encodings that are known to be remotely exploitable" },

    { DOUBLE_OPT, Parameter::PT_IMPLIED, nullptr, nullptr,
      "detects a double ASCII encoding that is larger than a standard buffer" },

    { PRINT_OPT, Parameter::PT_IMPLIED, nullptr, nullptr,
      "dump decode data to console; always true" },

    { LENGTH_OPT, Parameter::PT_INT, "0:", nullptr,
      "compares ASN.1 type lengths with the supplied argument" },

    { ABS_OFFSET_OPT, Parameter::PT_INT, "0:", nullptr,
      "absolute offset from the beginning of the packet" },

    { REL_OFFSET_OPT, Parameter::PT_INT, nullptr, nullptr,
      "relative offset from the cursor" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Asn1Module : public Module
{
public:
    Asn1Module() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &asn1PerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    ASN1_CTXT data;
};

bool Asn1Module::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool Asn1Module::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is(BITSTRING_OPT) )
        data.bs_overflow = 1;

    else if ( v.is(DOUBLE_OPT) )
        data.double_overflow = 1;

    else if ( v.is(PRINT_OPT) )
        data.print = 1;

    else if ( v.is(LENGTH_OPT) )
    {
        data.length = 1;
        data.max_length = v.get_long();
    }
    else if ( v.is(ABS_OFFSET_OPT) )
    {
        data.offset_type = ABS_OFFSET;
        data.offset = v.get_long();
    }
    else if ( v.is(REL_OFFSET_OPT) )
    {
        data.offset_type = REL_OFFSET;
        data.offset = v.get_long();
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Asn1Module;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* asn1_ctor(Module* p, OptTreeNode*)
{
    Asn1Module* m = (Asn1Module*)p;
    return new Asn1Option(m->data);
}

static void asn1_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi asn1_api =
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
    asn1_init_mem,
    asn1_free_mem,
    nullptr,
    nullptr,
    asn1_ctor,
    asn1_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_asn1[] =
#endif
{
    &asn1_api.base,
    nullptr
};

