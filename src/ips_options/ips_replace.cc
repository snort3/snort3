//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "actions/act_replace.h"
#include "detection/treenodes.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "packet_io/sfdaq.h"
#include "parser/parse_utils.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;
using namespace std;

static void replace_parse(const char* args, string& s)
{
    bool negated;

    if ( !parse_byte_code(args, negated, s) )
        return;

    if ( negated )
        ParseError("can't negate replace string");
}

static bool replace_ok()
{
    if ( SnortConfig::inline_mode() and SFDAQ::can_replace() )
        return true;

    static THREAD_LOCAL bool warned = false;

    if ( !warned )
    {
        WarningMessage("%s\n",
            "WARNING: replace requires inline mode and DAQ with replace capability");
        warned = true;
    }
    return false;
}

//-------------------------------------------------------------------------
// replace rule option
//-------------------------------------------------------------------------

#define s_name "replace"

static THREAD_LOCAL ProfileStats replacePerfStats;

class ReplaceOption : public IpsOption
{
public:
    ReplaceOption(string&);
    ~ReplaceOption() override;

    EvalStatus eval(Cursor&, Packet*) override;
    void action(Packet*) override;

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_agent() override
    { return true; }

    bool is_relative() override
    { return true; }

    void store(int off)
    { offset[get_instance_id()] = off; }

    bool pending()
    { return offset[get_instance_id()] >= 0; }

    int pos()
    { return offset[get_instance_id()]; }

private:
    string repl;
    int* offset; /* >=0 is offset to start of replace */
};

ReplaceOption::ReplaceOption(string& s) : IpsOption(s_name)
{
    unsigned n = ThreadConfig::get_instance_max();
    offset = new int[n];

    for ( unsigned i = 0; i < n; i++ )
        offset[i] = -1;

    repl = s;
}

ReplaceOption::~ReplaceOption()
{
    delete[] offset;
}

uint32_t ReplaceOption::hash() const
{
    uint32_t a,b,c;

    const char* s = repl.c_str();
    unsigned n = repl.size();

    a = 0;
    b = n;
    c = 0;

    mix(a,b,c);
    mix_str(a,b,c,s,n);
    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool ReplaceOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const ReplaceOption& rhs = (const ReplaceOption&)ips;

    if ( repl != rhs.repl )
        return false;

    return true;
}

IpsOption::EvalStatus ReplaceOption::eval(Cursor& c, Packet* p)
{
    Profile profile(replacePerfStats);

    if ( p->is_cooked() )
        return NO_MATCH;

    if ( !c.is("pkt_data") )
        return NO_MATCH;

    if ( c.get_pos() < repl.size() )
        return NO_MATCH;

    if ( replace_ok() )
        store(c.get_pos() - repl.size());

    return MATCH;
}

void ReplaceOption::action(Packet*)
{
    Profile profile(replacePerfStats);

    if ( pending() )
        Replace_QueueChange(repl, (unsigned)pos());
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "byte code to replace with" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to overwrite payload data; use with rewrite action"

class ReplModule : public Module
{
public:
    ReplModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &replacePerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    string data;
};

bool ReplModule::begin(const char*, int, SnortConfig*)
{
    data.clear();
    return true;
}

bool ReplModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~") )
        replace_parse(v.get_string(), data);

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ReplModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* replace_ctor(Module* p, OptTreeNode*)
{
    ReplModule* m = (ReplModule*)p;
    return new ReplaceOption(m->data);
}

static void replace_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi replace_api =
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
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    replace_ctor,
    replace_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_replace[] =
#endif
{
    &replace_api.base,
    nullptr
};

