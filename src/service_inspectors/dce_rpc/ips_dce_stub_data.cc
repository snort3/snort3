//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// ips_dce_stub_data.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"

#include "dce_common.h"

using namespace snort;

#define s_name "dce_stub_data"
#define s_help \
    "sets the cursor to dcerpc stub data"

//-------------------------------------------------------------------------
// dcerpc2 stub data rule option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats dce2_stub_data_perf_stats;

class Dce2StubDataOption : public IpsOption
{
public:
    Dce2StubDataOption() : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_SET) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;
};

uint32_t Dce2StubDataOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;

    mix_str(a, b, c, get_name());
    finalize(a,b,c);

    return c;
}

bool Dce2StubDataOption::operator==(const IpsOption& ips) const
{
    return !strcmp(get_name(), ips.get_name());
}

IpsOption::EvalStatus Dce2StubDataOption::eval(Cursor& c, Packet* p)
{
    Profile profile(dce2_stub_data_perf_stats);

    if (p->dsize == 0)
    {
        return NO_MATCH;
    }

    if (DceContextData::is_noinspect(p))
    {
        return NO_MATCH;
    }

    DCE2_Roptions* ropts = DceContextData::get_current_ropts(p);

    if ( !ropts )
        return NO_MATCH;

    if (ropts->stub_data != nullptr)
    {
        c.set(s_name, ropts->stub_data, (uint16_t)(p->dsize - (ropts->stub_data -
            p->data)));
        return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class Dce2StubDataModule : public Module
{
public:
    Dce2StubDataModule() : Module(s_name, s_help) { }
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }
};

ProfileStats* Dce2StubDataModule::get_profile() const
{
    return &dce2_stub_data_perf_stats;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* dce2_stub_data_mod_ctor()
{
    return new Dce2StubDataModule;
}

static void dce2_stub_data_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dce2_stub_data_ctor(Module*, OptTreeNode*)
{
    return new Dce2StubDataOption;
}

static void dce2_stub_data_dtor(IpsOption* p)
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
        dce2_stub_data_mod_ctor,
        dce2_stub_data_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    dce2_stub_data_ctor,
    dce2_stub_data_dtor,
    nullptr
};

const BaseApi* ips_dce_stub_data = &ips_api.base;

