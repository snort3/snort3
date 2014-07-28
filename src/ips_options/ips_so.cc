/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "framework/so_rule.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
using namespace std;

#include "framework/parameter.h"
#include "framework/module.h"
#include "managers/ips_manager.h"
#include "hash/sfhashfcn.h"
#include "parser/parser.h"
#include "time/profiler.h"

static const char* s_name = "so";

static THREAD_LOCAL ProfileStats soPerfStats;

class SoOption : public IpsOption
{
public:
    SoOption(const char*, const char*, SoEvalFunc f, void* v);
    ~SoOption();

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    const char* soid;
    const char* so;
    SoEvalFunc func;
    void* data;
};

SoOption::SoOption(
    const char* id, const char* s, SoEvalFunc f, void* v)
    : IpsOption(s_name)
{
    soid = id;
    so = s;
    func = f;
    data = v;
}

SoOption::~SoOption()
{
    if ( data )
        IpsManager::delete_so_data(soid, data);
}

uint32_t SoOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;
    mix_str(a,b,c,soid);
    mix_str(a,b,c,so);
    final(a,b,c);
    return c;
}

bool SoOption::operator==(const IpsOption& ips) const
{
    SoOption& rhs = (SoOption&)ips;

    if ( strcmp(soid, rhs.soid) )
        return false;

    if ( strcmp(so, rhs.so) )
        return false;

    return true;
}

int SoOption::eval(Cursor&, Packet* p)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(soPerfStats);

    int ret = func(data, p);

    MODULE_PROFILE_END(soPerfStats);
    return ret;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter so_params[] =
{
    { "*func", Parameter::PT_STRING, nullptr, nullptr,
      "name of function to call" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SoModule : public Module
{
public:
    SoModule() : Module(s_name, so_params) { };

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &soPerfStats; };

    string name;
};

bool SoModule::begin(const char*, int, SnortConfig*)
{
    name.clear();
    return true;
}

bool SoModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("*func") )
        name = v.get_string();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new SoModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* so_ctor(Module* p, OptTreeNode* otn)
{
    void* data = nullptr;
    SoModule* m = (SoModule*)p;
    const char* name = m->name.c_str();

    SoEvalFunc func = IpsManager::get_so_eval(otn->soid, name, &data);

    if ( !func )
    {
        ParseError("Can't link so:%s", name);
        return nullptr;
    }
    return new SoOption(otn->soid, name, func, data);
}

static void so_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi so_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, 0x0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    so_ctor,
    so_dtor,
    nullptr
};

const BaseApi* ips_so = &so_api.base;

