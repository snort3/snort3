//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// ips_so.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/treenodes.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/so_rule.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/so_manager.h"
#include "profiler/profiler.h"

using namespace snort;
using namespace std;

#define s_name "so"

static THREAD_LOCAL ProfileStats soPerfStats;

class SoOption : public IpsOption
{
public:
    SoOption(const char*, const char*, bool, SoEvalFunc f, void* v, SnortConfig*);
    ~SoOption() override;

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_relative() override
    { return relative_flag; }

    EvalStatus eval(Cursor&, Packet*) override;

    CursorActionType get_cursor_type() const override
    { return CAT_READ; }

private:
    const char* soid;
    const char* so;
    bool relative_flag;
    SoEvalFunc func;
    void* data;
    SoRules* so_rules;
};

SoOption::SoOption(
    const char* id, const char* s, bool r, SoEvalFunc f, void* v, SnortConfig* sc)
    : IpsOption(s_name)
{
    soid = id;
    so = s;
    relative_flag = r;
    func = f;
    data = v;
    so_rules = sc->so_rules;
}

SoOption::~SoOption()
{
    SoManager::delete_so_data(soid, data, so_rules);
}

uint32_t SoOption::hash() const
{
    uint32_t a = relative_flag, b = IpsOption::hash(), c = 0;
    mix_str(a,b,c,soid);
    mix_str(a,b,c,so);
    finalize(a,b,c);
    return c;
}

bool SoOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const SoOption& rhs = (const SoOption&)ips;

    if ( strcmp(soid, rhs.soid) )
        return false;

    if ( strcmp(so, rhs.so) )
        return false;

    if ( relative_flag != rhs.relative_flag )
        return false;

    return true;
}

IpsOption::EvalStatus SoOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(soPerfStats);
    return func(data, c, p);
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~func", Parameter::PT_STRING, nullptr, nullptr,
      "name of eval function" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "offset from cursor instead of start of buffer" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to call custom eval function"

class SoModule : public Module
{
public:
    SoModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &soPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    string name;
    bool relative_flag = false;
    SnortConfig* cfg = nullptr;
};

bool SoModule::begin(const char*, int, SnortConfig* sc)
{
    name.clear();
    relative_flag = false;
    cfg = sc;
    return true;
}

bool SoModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~func") )
        name = v.get_string();

    else if ( v.is("relative") )
        relative_flag = true;

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
    bool relative_flag = m->relative_flag;

    if ( !otn->soid )
    {
        ParseError("no soid before so:%s", name);
        return nullptr;
    }
    SoEvalFunc func = SoManager::get_so_eval(otn->soid, name, &data, m->cfg);

    if ( !func )
    {
        ParseError("can't link so:%s", name);
        return nullptr;
    }
    return new SoOption(otn->soid, name, relative_flag, func, data, m->cfg);
}

static void so_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi so_api =
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

