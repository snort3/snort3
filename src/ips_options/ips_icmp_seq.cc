//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_icmp_seq.cc author Russ Combs <rucombs@cisco.com>

/* sp_icmp_seq_check
 *
 * Purpose:
 *
 * Test the Sequence number field of ICMP ECHO and ECHO_REPLY packets for
 * specified values.  This is useful for detecting TFN attacks, amongst others.
 *
 * Arguments:
 *
 * The ICMP Seq plugin takes a number as an option argument.
 *
 * Effect:
 *
 * Tests ICMP ECHO and ECHO_REPLY packet Seq field values and returns a
 * "positive" detection result (i.e. passthrough) upon a value match.
 *
 * Comments:
 *
 * This plugin was developed to detect TFN distributed attacks.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "icmp_seq"

static THREAD_LOCAL ProfileStats icmpSeqPerfStats;

class IcmpSeqOption : public IpsOption
{
public:
    IcmpSeqOption(const RangeCheck& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IcmpSeqOption::hash() const
{
    uint32_t a,b,c;

    a = config.op;
    b = config.min;
    c = config.max;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool IcmpSeqOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const IcmpSeqOption& rhs = (const IcmpSeqOption&)ips;
    return ( config == rhs.config );
}

IpsOption::EvalStatus IcmpSeqOption::eval(Cursor&, Packet* p)
{
    Profile profile(icmpSeqPerfStats);

    if (!p->ptrs.icmph)
        return NO_MATCH;

    if ( (p->ptrs.icmph->type == ICMP_ECHO ||
        p->ptrs.icmph->type == ICMP_ECHOREPLY) ||
        ((uint8_t)p->ptrs.icmph->type == icmp::Icmp6Types::ECHO_REQUEST ||
        (uint8_t)p->ptrs.icmph->type == icmp::Icmp6Types::ECHO_REPLY) )
    {
        uint16_t icmp_seq = ntohs(p->ptrs.icmph->s_icmp_seq);

        if ( config.eval( icmp_seq ) )
            return MATCH;
    }
    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:65535"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "check if ICMP sequence number is in given range" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check ICMP sequence number"

class IcmpSeqModule : public Module
{
public:
    IcmpSeqModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &icmpSeqPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck data;
};

bool IcmpSeqModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool IcmpSeqModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~range") )
        return false;

    return data.validate(v.get_string(), RANGE);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new IcmpSeqModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* icmp_seq_ctor(Module* p, OptTreeNode*)
{
    IcmpSeqModule* m = (IcmpSeqModule*)p;
    return new IcmpSeqOption(m->data);
}

static void icmp_seq_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi icmp_seq_api =
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
    1, PROTO_BIT__ICMP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    icmp_seq_ctor,
    icmp_seq_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_icmp_seq[] =
#endif
{
    &icmp_seq_api.base,
    nullptr
};

