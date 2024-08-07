//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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

// ips_s7comm_transport_size.cc author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <iostream> // For debug output
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "s7comm.h"

using namespace snort;

static const char* s_name = "s7comm_pi_transport_size";

//-------------------------------------------------------------------------
// transport_size option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7comm_transport_size_prof;

class S7commTransportSizeOption : public IpsOption
{
public:
    S7commTransportSizeOption(uint8_t v) : IpsOption(s_name), transport_size(v) {}

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint8_t transport_size;
};

uint32_t S7commTransportSizeOption::hash() const
{
    uint32_t a = transport_size, b = IpsOption::hash(), c = 0;
    mix(a, b, c);
    finalize(a, b, c);
    return c;
}

bool S7commTransportSizeOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const S7commTransportSizeOption& rhs = (const S7commTransportSizeOption&)ips;
    return (transport_size == rhs.transport_size);
}

IpsOption::EvalStatus S7commTransportSizeOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(s7comm_transport_size_prof);

    if (!p->flow)
        return NO_MATCH;

    if (!p->is_full_pdu())
        return NO_MATCH;

    S7commFlowData* mfd = (S7commFlowData*)p->flow->get_flow_data(S7commFlowData::inspector_id);

    if (!mfd)
        return NO_MATCH;

    for (const auto& requestItem : mfd->ssn_data.request_items)
    {        
        if (requestItem.transport_size == transport_size)
            return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr, "transport_size to match" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check s7comm transport_size"

class S7commTransportSizeModule : public Module
{
public:
    S7commTransportSizeModule() : Module(s_name, s_help, s_params) {}

    bool set(const char*, Value&, SnortConfig*) override;
    ProfileStats* get_profile() const override { return &s7comm_transport_size_prof; }
    Usage get_usage() const override { return DETECT; }

public:
    uint8_t transport_size = 0;
};

bool S7commTransportSizeModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if (v.strtol(n))
        transport_size = static_cast<uint8_t>(n);

    return true;
}

static Module* mod_ctor()
{
    return new S7commTransportSizeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    S7commTransportSizeModule* mod = (S7commTransportSizeModule*)m;
    return new S7commTransportSizeOption(mod->transport_size);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
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
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_s7comm_pi_transport_size = &ips_api.base;
