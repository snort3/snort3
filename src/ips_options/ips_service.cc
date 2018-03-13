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
// ips_service.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/decode_data.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "log/messages.h"
#include "parser/parse_conf.h"

using namespace snort;
using namespace std;

#define s_name "service"

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "*", Parameter::PT_STRING, nullptr, nullptr,
      "one or more comma-separated service names" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to specify list of services for grouping rules"

class ServiceModule : public Module
{
public:
    ServiceModule() : Module(s_name, s_help, s_params)
    { snort_config = nullptr; }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return DETECT; }

public:
    struct SnortConfig* snort_config;
    vector<string> services;
};

bool ServiceModule::begin(const char*, int, SnortConfig* sc)
{
    snort_config = sc;
    services.clear();
    return true;
}

bool ServiceModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("*") )
        return false;

    std::string svc = v.get_string();

    for ( const auto& p : services )
    {
        if ( p == svc )
        {
            ParseWarning(WARN_RULES, "repeated service '%s'", svc.c_str());
            return true;
        }
    }
    services.push_back(svc);

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ServiceModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* service_ctor(Module* p, OptTreeNode* otn)
{
    ServiceModule* m = (ServiceModule*)p;

    for ( const auto& service : m->services )
        add_service_to_otn(m->snort_config, otn, service.c_str());

    return nullptr;
}

static const IpsApi service_api =
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
    0, PROTO_BIT__NONE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    service_ctor,
    nullptr,
    nullptr
};

const BaseApi* ips_service = &service_api.base;

