//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// ips_dnp3_data.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Ryan Jordan

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "dnp3.h"

using namespace snort;

#define s_name "dnp3_data"
#define s_help \
    "sets the cursor to dnp3 data"

//-------------------------------------------------------------------------
// DNP3 data rule option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats dnp3_data_perf_stats;

class Dnp3DataOption : public IpsOption
{
public:
    Dnp3DataOption() : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_SET) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;
};

uint32_t Dnp3DataOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;

    mix_str(a, b, c, get_name());
    finalize(a,b,c);

    return c;
}

bool Dnp3DataOption::operator==(const IpsOption& ips) const
{
    return !strcmp(get_name(), ips.get_name());
}

IpsOption::EvalStatus Dnp3DataOption::eval(Cursor& c, Packet* p)
{
    Profile profile(dnp3_data_perf_stats);

    if ((p->has_tcp_data() && !p->is_full_pdu()) || !p->flow || !p->dsize)
        return NO_MATCH;

    Dnp3FlowData* fd = (Dnp3FlowData*)p->flow->get_flow_data(Dnp3FlowData::inspector_id);

    if (!fd)
        return NO_MATCH;

    dnp3_session_data_t* dnp3_session = &fd->dnp3_session;
    dnp3_reassembly_data_t* rdata;

    if (dnp3_session->direction == DNP3_CLIENT)
        rdata = &(dnp3_session->client_rdata);
    else
        rdata = &(dnp3_session->server_rdata);

    /* Only evaluate rules against complete Application-layer fragments */
    if (rdata->state != DNP3_REASSEMBLY_STATE__DONE)
        return NO_MATCH;

    c.set(s_name,(uint8_t*)rdata->buffer, rdata->buflen);

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class Dnp3DataModule : public Module
{
public:
    Dnp3DataModule() : Module(s_name, s_help) { }
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }
};

ProfileStats* Dnp3DataModule::get_profile() const
{
    return &dnp3_data_perf_stats;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* dnp3_data_mod_ctor()
{
    return new Dnp3DataModule;
}

static void dnp3_data_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dnp3_data_ctor(Module*, OptTreeNode*)
{
    return new Dnp3DataOption;
}

static void dnp3_data_dtor(IpsOption* p)
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
        dnp3_data_mod_ctor,
        dnp3_data_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    dnp3_data_ctor,
    dnp3_data_dtor,
    nullptr
};

const BaseApi* ips_dnp3_data = &ips_api.base;

