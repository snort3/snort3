/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
// wizard.cc author Russ Combs <rucombs@cisco.com>

#include "wizard.h"

#include <vector>
using namespace std;

#include "wiz_module.h"
#include "flow/flow.h"
#include "framework/inspector.h"
#include "stream/stream_splitter.h"
#include "managers/inspector_manager.h"
#include "protocols/packet.h"
#include "stream/stream_api.h"
#include "stream/stream_splitter.h"
#include "time/profiler.h"
#include "utils/stats.h"
#include "log/messages.h"

static const char* mod_name = "wizard";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats wizPerfStats;

static PreprocStats* wiz_get_profile(const char* key)
{
    if ( !strcmp(key, mod_name) )
        return &wizPerfStats;

    return nullptr;
}
#endif

struct WizStats
{
    PegCount tcp_scans;
    PegCount tcp_hits;
    PegCount udp_pkts;
    PegCount udp_hits;
};

static const char* wiz_pegs[] =
{
    "tcp scans",
    "tcp hits",
    "udp packets",
    "udp hits"
};

static THREAD_LOCAL WizStats tstats;
static WizStats gstats;

//-------------------------------------------------------------------------
// configuration
// -- spells are used for text protocols
// -- must compile spells into fsm like hi paf
//
// -- hexes are used for binary protocols
// -- must build a tree trie like file magic
//-------------------------------------------------------------------------

struct Spell
{
    const char* dummy;
};

struct Hex
{
    const char* dummy;
};

struct Wand
{
    unsigned index;
};

class Wizard;

class MagicSplitter : public StreamSplitter
{
public:
    MagicSplitter(bool, class Wizard*);
    ~MagicSplitter();

    PAF_Status scan(Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp);

    bool is_paf() { return true; };

private:
    Wizard* wizard;
    Wand wand;
};

class Wizard : public Inspector {
public:
    Wizard();
    ~Wizard();

    void show(SnortConfig*)
    { LogMessage("Wizard\n"); };

    void eval(Packet*);

    StreamSplitter* get_splitter(bool);

    bool check(Wand&, const uint8_t*, unsigned, vector<Spell>&, vector<Hex>&);

public:
    vector<Spell> tcp_c2s_spells;
    vector<Spell> tcp_s2c_spells;

    vector<Spell> udp_c2s_spells;
    vector<Spell> udp_s2c_spells;

    vector<Hex> tcp_c2s_hexes;
    vector<Hex> tcp_s2c_hexes;

    vector<Hex> udp_c2s_hexes;
    vector<Hex> udp_s2c_hexes;
};

//-------------------------------------------------------------------------
// splitter - this doesn't actually split the stream but it applies 
// basic magic type logic to determine the appropriate inspector that
// will split the stream.
//-------------------------------------------------------------------------

MagicSplitter::MagicSplitter(bool c2s, class Wizard* w) : StreamSplitter(c2s)
{
    wizard = w;
    w->add_ref();
}

MagicSplitter::~MagicSplitter()
{
    wizard->rem_ref();
}

PAF_Status MagicSplitter::scan (
    Flow*, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    ++tstats.tcp_scans;

    if ( to_server() )
    {
        if ( wizard->check(wand, data, len, wizard->tcp_c2s_spells, wizard->tcp_c2s_hexes) )
        { 
            /* set inspector gadget */
            // len + 1 means go back to the last flush point
            // (0 means start of this buffer)
            *fp = len + 1;
            return PAF_RESET;
        }
    }
    else
    {
        if ( wizard->check(wand, data, len, wizard->tcp_s2c_spells, wizard->tcp_s2c_hexes) )
        { 
            /* set inspector gadget */
            *fp = len + 1;
            return PAF_RESET;
        }
    }
    return PAF_SEARCH;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

Wizard::Wizard()
{
}

Wizard::~Wizard()
{
}

void Wizard::eval(Packet* p)
{
    if ( !IsUDP(p) )
        return;

    if ( !p->data || !p->dsize )
        return;

    Wand wand;

    if ( p->packet_flags & PKT_FROM_CLIENT )
    {
        if ( check(wand, p->data, p->dsize, udp_c2s_spells, udp_c2s_hexes) )
        { /* set inspector gadget */ }
    }

    else
    {
        if ( check(wand, p->data, p->dsize, udp_s2c_spells, udp_s2c_hexes) )
        { /* set inspector gadget */ }
    }

    ++tstats.udp_pkts;
}

StreamSplitter* Wizard::get_splitter(bool c2s)
{
    return new MagicSplitter(c2s, this);
}

bool Wizard::check(
    Wand&, const uint8_t* data, unsigned len, vector<Spell>&, vector<Hex>&)
{
    // this is a basic hack to find http requests so that the overall
    // processing flow can be determined at which point the real magic
    // can begin.

    if ( len >= 3 && !strncmp((const char*)data, "GET", 3) )
    {
        // FIXIT here we have determined that the inspector should
        // be http and must somehow tell the binder so it can set 
        // inspector gadget.

        // the real magic must check direction and protocol
        // (and should be called from eval() for udp and from
        // here for tcp).

        // the reset status ensures that all the
        // data scanned so far is delivered to the new inspector's
        // splitter.
        ++tstats.tcp_hits;
        return true;
    }
    return false;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new WizardModule; }

static void mod_dtor(Module* m)
{ delete m; }

void wiz_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        mod_name, &wizPerfStats, 0, &totalPerfStats, wiz_get_profile);
#endif
}

static Inspector* wiz_ctor(Module* m)
{
    WizardModule* mod = (WizardModule*)m;
    assert(mod);
    return new Wizard;
}

static void wiz_dtor(Inspector* p)
{
    delete p;
}

static void wiz_sum()
{
    sum_stats((PegCount*)&gstats, (PegCount*)&tstats, array_size(wiz_pegs));
}

static void wiz_stats()
{
    show_stats((PegCount*)&gstats, wiz_pegs, array_size(wiz_pegs), mod_name);
}

static void wiz_reset()
{
    memset(&gstats, 0, sizeof(gstats));
}

static const InspectApi wiz_api =
{
    {
        PT_INSPECTOR,
        mod_name,
        INSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    IT_WIZARD, 
    PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr, // buffers
    nullptr, // service
    wiz_init,
    nullptr, // term
    wiz_ctor,
    wiz_dtor,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // ssn
    wiz_sum,
    wiz_stats,
    wiz_reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &wiz_api.base,
    nullptr
};
#else
const BaseApi* sin_wizard = &wiz_api.base;
#endif

