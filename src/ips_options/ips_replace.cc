/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#include "ips_replace.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string>
using namespace std;

#include "snort_types.h"
#include "snort_bounds.h"
#include "snort_debug.h"
#include "protocols/packet.h"
#include "parser.h"
#include "parser/parse_byte_code.h"
#include "ips_content.h"
#include "snort.h"
#include "packet_io/sfdaq.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"
#include "detection/detection_defines.h"

#define MAX_PATTERN_SIZE 2048

static void replace_parse(const char* args, string& s)
{
    bool negated;
    std::string buf;

    if ( !parse_byte_code(args, negated, s) )
        return;

    if ( negated )
        ParseError("can't negate replace string");
}

static bool replace_ok()
{
    static int warned = 0;

    if ( !ScInlineMode() )
        return false;

    if ( !DAQ_CanReplace() )
    {
        if ( !warned )
        {
            LogMessage("WARNING: payload replacements disabled because DAQ "
                " can't replace packets.\n");
            warned = 1;
        }
        return false;
    }
    return true;
}

//--------------------------------------------------------------------------
// queue foo
//--------------------------------------------------------------------------

struct Replacement
{
    string data;
    int offset;
};

#define MAX_REPLACEMENTS 32
static THREAD_LOCAL Replacement* rpl;
static THREAD_LOCAL int num_rpl = 0;

void Replace_ResetQueue(void)
{
    num_rpl = 0;
}

void Replace_QueueChange(string& s, int off)
{
    Replacement* r;

    if ( num_rpl == MAX_REPLACEMENTS )
        return;

    r = rpl + num_rpl++;

    r->data = s;
    r->offset = off;
}

static inline void Replace_ApplyChange(Packet *p, Replacement* r)
{
    uint8_t* start = (uint8_t*)p->data + r->offset;
    const uint8_t* end = p->data + p->dsize;
    unsigned len;

    if ( (start + r->data.size()) >= end )
        len = p->dsize - r->offset;
    else
        len = r->data.size();

    memcpy(start, r->data.c_str(), len);
}

// FIXIT this could be ContentOption::action()
// for a more general packet rewriting facility
void Replace_ModifyPacket(Packet *p)
{
    if ( num_rpl == 0 )
        return;

    for ( int n = 0; n < num_rpl; n++ )
    {
        Replace_ApplyChange(p, rpl+n);
    }
    p->packet_flags |= PKT_MODIFIED;
    num_rpl = 0;
}

//-------------------------------------------------------------------------
// replace rule option
//-------------------------------------------------------------------------

static const char* s_name = "replace";

static THREAD_LOCAL ProfileStats replacePerfStats;

class ReplaceOption : public IpsOption
{
public:
    ReplaceOption(string&);
    ~ReplaceOption();

    int eval(Cursor&, Packet*);
    void action(Packet*);

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    void store(int off)
    { offset[get_instance_id()] = off; };

    bool pending()
    { return offset[get_instance_id()] >= 0; };

    int pos()
    { return offset[get_instance_id()]; };
private:
    string repl;
    int* offset; /* >=0 is offset to start of replace */
};

ReplaceOption::ReplaceOption(string& s) : IpsOption(s_name)
{
    unsigned n = get_instance_max();
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
    final(a,b,c);

    return c;
}

bool ReplaceOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    ReplaceOption& rhs = (ReplaceOption&)ips;

    if ( repl != rhs.repl )
        return false;

    return true;
}

int ReplaceOption::eval(Cursor& c, Packet* p)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(replacePerfStats);

    if ( PacketWasCooked(p) )
        return false;

    if ( !c.is("pkt_data") )
        return DETECTION_OPTION_NO_MATCH;

    if ( c.length() < repl.size() )
        return DETECTION_OPTION_NO_MATCH;

    store(c.get_pos());

    MODULE_PROFILE_END(replacePerfStats);
    return DETECTION_OPTION_MATCH;
}

// FIXIT this may need to be apply change here
// and queue change from some other point
// (almost certainly broke)
void ReplaceOption::action(Packet*)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(replacePerfStats);

    if ( pending() )
        Replace_QueueChange(repl, pos());

    MODULE_PROFILE_END(replacePerfStats);
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter repl_params[] =
{
    { "~mode", Parameter::PT_ENUM, "printable|binary|all", nullptr,
      "output format" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ReplModule : public Module
{
public:
    ReplModule() : Module(s_name, repl_params) { };

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &replacePerfStats; };

    string data;
};

bool ReplModule::begin(const char*, int, SnortConfig*)
{
    data.clear();
    return true;
}

bool ReplModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~mode") )
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

static IpsOption* replace_ctor(Module* p, OptTreeNode* otn)
{
    if ( !replace_ok() )
        ParseError("Inline mode and DAQ with replace capabilities required "
            "to use rule option 'replace'.");

    ReplModule* m = (ReplModule*)p;
    ReplaceOption* opt = new ReplaceOption(m->data);

    if ( otn_set_agent(otn, opt) )
        return opt;

    delete opt;
    ParseError("At most one action per rule is allowed");
    return nullptr;
}

static void replace_dtor(IpsOption* p)
{
    delete p;
}

static void replace_tinit(SnortConfig*)
{
    rpl = new Replacement[MAX_REPLACEMENTS];
}

static void replace_tterm(SnortConfig*)
{
    delete[] rpl;
}

static const IpsApi replace_api =
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
    0, 0,
    nullptr,
    nullptr,
    replace_tinit,
    replace_tterm,
    replace_ctor,
    replace_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &replace_api.base,
    nullptr
};
#else
const BaseApi* ips_replace = &replace_api.base;
#endif

