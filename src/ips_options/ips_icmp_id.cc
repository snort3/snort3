//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// ips_icmp_id.cc author Russ Combs <rucombs@cisco.com>

/* sp_icmp_id
 *
 * Purpose:
 *
 * Test the ID field of ICMP ECHO and ECHO_REPLY packets for specified
 * values.  This is useful for detecting TFN attacks, amongst others.
 *
 * Arguments:
 *
 * The ICMP ID plugin takes a number as an option argument.
 *
 * Effect:
 *
 * Tests ICMP ECHO and ECHO_REPLY packet ID field values and returns a
 * "positive" detection result (i.e. passthrough) upon a value match.
 *
 * Comments:
 *
 * This plugin was developed to detect TFN distributed attacks.
 *
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "hash/sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"
#include "framework/range.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"

#define s_name "icmp_id"

static THREAD_LOCAL ProfileStats icmpIdPerfStats;

class IcmpIdOption : public IpsOption
{
public:
    IcmpIdOption(const RangeCheck& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IcmpIdOption::hash() const
{
    uint32_t a,b,c;

    a = config.op;
    b = config.min;
    c = config.max;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool IcmpIdOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IcmpIdOption& rhs = (IcmpIdOption&)ips;
    return ( config == rhs.config );
}

int IcmpIdOption::eval(Cursor&, Packet* p)
{
    Profile profile(icmpIdPerfStats);

    if (!p->ptrs.icmph)
        return DETECTION_OPTION_NO_MATCH;


    if ( (p->ptrs.icmph->type == ICMP_ECHO ||
        p->ptrs.icmph->type == ICMP_ECHOREPLY) ||
        ((uint16_t)p->ptrs.icmph->type == icmp::Icmp6Types::ECHO_REQUEST ||
        (uint16_t)p->ptrs.icmph->type == icmp::Icmp6Types::ECHO_REPLY) )
    {
        if ( config.eval(p->ptrs.icmph->s_icmp_id) )
            return DETECTION_OPTION_MATCH;
    }

    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_STRING, nullptr, nullptr,
      "check if icmp id is 'id | min<>max | <max | >min'" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check ICMP ID"

class IcmpIdModule : public Module
{
public:
    IcmpIdModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &icmpIdPerfStats; }

    RangeCheck data;
};

bool IcmpIdModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool IcmpIdModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~range") )
        return false;

    return data.parse(v.get_string());
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new IcmpIdModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* icmp_id_ctor(Module* p, OptTreeNode*)
{
    IcmpIdModule* m = (IcmpIdModule*)p;
    return new IcmpIdOption(m->data);
}

static void icmp_id_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi icmp_id_api =
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
    icmp_id_ctor,
    icmp_id_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &icmp_id_api.base,
    nullptr
};
#else
const BaseApi* ips_icmp_id = &icmp_id_api.base;
#endif

