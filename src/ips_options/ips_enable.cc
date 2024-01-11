//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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
// ips_enable.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/treenodes.h"
#include "detection/rules.h"
#include "framework/decode_data.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "main/snort_config.h"

using namespace snort;

#define s_name "enable"

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~enable", Parameter::PT_ENUM, "no | yes | inherit", "yes",
      "enable or disable rule in current ips policy or use default defined by ips policy" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "stub rule option to enable or disable full rule"

class EnableModule : public Module
{
public:
    EnableModule() : Module(s_name, s_help, s_params) { }
    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    Usage get_usage() const override
    { return DETECT; }

public:
    IpsPolicy::Enable enable = IpsPolicy::Enable::ENABLED;
};

bool EnableModule::begin(const char*, int, SnortConfig* sc)
{
    if ( !sc->rule_states )
        sc->rule_states = new RuleStateMap;

    enable = IpsPolicy::Enable::ENABLED;
    return true;
}

bool EnableModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~enable"));
    enable = IpsPolicy::Enable(v.get_uint8());
    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new EnableModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* enable_ctor(Module* p, OptTreeNode* otn)
{
    EnableModule* m = (EnableModule*)p;
    otn->set_enabled(m->enable);
    return nullptr;
}

static const IpsApi enable_api =
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
    OPT_TYPE_META,
    1, PROTO_BIT__NONE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    enable_ctor,
    nullptr,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_enable[] =
#endif
{
    &enable_api.base,
    nullptr
};

