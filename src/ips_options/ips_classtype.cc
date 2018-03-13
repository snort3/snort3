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
// ips_classtype.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/treenodes.h"
#include "framework/decode_data.h"
#include "framework/ips_option.h"
#include "framework/module.h"

using namespace snort;

#define s_name "classtype"

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "classification for this rule" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "general rule option for rule classification"

class ClassTypeModule : public Module
{
public:
    ClassTypeModule() : Module(s_name, s_help, s_params) { }
    bool set(const char*, Value&, SnortConfig*) override;

    Usage get_usage() const override
    { return DETECT; }

public:
    ClassType* type;
};

bool ClassTypeModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( !v.is("~") )
        return false;

    type = ClassTypeLookupByType(sc, v.get_string());

    return type != nullptr;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ClassTypeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* classtype_ctor(Module* p, OptTreeNode* otn)
{
    ClassTypeModule* m = (ClassTypeModule*)p;
    otn->sigInfo.class_type = m->type;

    if ( m->type )
    {
        otn->sigInfo.class_id = m->type->id;
        otn->sigInfo.priority = m->type->priority;
    }
    return nullptr;
}

static const IpsApi classtype_api =
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
    classtype_ctor,
    nullptr,
    nullptr
};

const BaseApi* ips_classtype = &classtype_api.base;

