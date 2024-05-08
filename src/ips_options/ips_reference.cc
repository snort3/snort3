//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// ips_reference.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/decode_data.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "main/snort_config.h"

using namespace snort;

#define s_name "reference"

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~ref", Parameter::PT_STRING, nullptr, nullptr,
      "reference: <scheme>,<id>" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to indicate relevant attack identification system"

class ReferenceModule : public Module
{
public:
    ReferenceModule() : Module(s_name, s_help, s_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return DETECT; }

public:
    std::string scheme;
    std::string id;
};

bool ReferenceModule::begin(const char*, int, SnortConfig*)
{
    scheme.clear();
    id.clear();
    return true;
}

bool ReferenceModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~ref"));

    const char* ref = v.get_string();
    const char* sep = strchr(ref, ',');

    if ( !sep or !strlen(sep + 1) )
        return false;

    scheme.assign(ref, sep - ref);
    id = sep + 1;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ReferenceModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* reference_ctor(Module* p, IpsInfo& info)
{
    ReferenceModule* m = (ReferenceModule*)p;
    IpsOption::add_reference(info, m->scheme.c_str(), m->id.c_str());
    return nullptr;
}

static const IpsApi reference_api =
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
    reference_ctor,
    nullptr,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_reference[] =
#endif
{
    &reference_api.base,
    nullptr
};

