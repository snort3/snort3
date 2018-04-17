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
// wizard.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_tracker/host_cache.h"
#include "flow/flow.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "stream/stream_splitter.h"

#include "curses.h"
#include "magic.h"
#include "wiz_module.h"

using namespace snort;
using namespace std;

THREAD_LOCAL ProfileStats wizPerfStats;

struct WizStats
{
    PegCount tcp_scans;
    PegCount tcp_hits;
    PegCount udp_scans;
    PegCount udp_hits;
    PegCount user_scans;
    PegCount user_hits;
};

const PegInfo wiz_pegs[] =
{
    { CountType::SUM, "tcp_scans", "tcp payload scans" },
    { CountType::SUM, "tcp_hits", "tcp identifications" },
    { CountType::SUM, "udp_scans", "udp payload scans" },
    { CountType::SUM, "udp_hits", "udp identifications" },
    { CountType::SUM, "user_scans", "user payload scans" },
    { CountType::SUM, "user_hits", "user identifications" },
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL WizStats tstats;

//-------------------------------------------------------------------------
// configuration
//-------------------------------------------------------------------------

struct CurseServiceTracker
{
    const CurseDetails* curse;
    CurseTracker* tracker;
};

struct Wand
{
    const MagicPage* hex;
    const MagicPage* spell;
    vector<CurseServiceTracker> curse_tracker;
};

class Wizard;

class MagicSplitter : public StreamSplitter
{
public:
    MagicSplitter(bool, class Wizard*);
    ~MagicSplitter() override;

    Status scan(Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }

private:
    void count_scan(const Flow* f)
    {
        if ( f->pkt_type == PktType::TCP )
            ++tstats.tcp_scans;
        else
            ++tstats.user_scans;
    }

    void count_hit(const Flow* f)
    {
        if ( f->pkt_type == PktType::TCP )
            ++tstats.tcp_hits;
        else
            ++tstats.user_hits;
    }

private:
    Wizard* wizard;
    Wand wand;
};

class Wizard : public Inspector
{
public:
    Wizard(WizardModule*);
    ~Wizard() override;

    void show(SnortConfig*) override
    { LogMessage("Wizard\n"); }

    void eval(Packet*) override;

    StreamSplitter* get_splitter(bool) override;

    void reset(Wand&, bool tcp, bool c2s);
    bool finished(Wand&);
    bool cast_spell(Wand&, Flow*, const uint8_t*, unsigned);
    bool spellbind(const MagicPage*&, Flow*, const uint8_t*, unsigned);
    bool cursebind(vector<CurseServiceTracker>&, Flow*, const uint8_t*, unsigned);

public:
    MagicBook* c2s_hexes;
    MagicBook* s2c_hexes;

    MagicBook* c2s_spells;
    MagicBook* s2c_spells;

    CurseBook* curses;
};

//-------------------------------------------------------------------------
// splitter - this doesn't actually split the stream but it applies
// basic magic type logic to determine the appropriate inspector that
// will split the stream.
//-------------------------------------------------------------------------

MagicSplitter::MagicSplitter(bool c2s, class Wizard* w) :
    StreamSplitter(c2s)
{
    wizard = w;
    w->add_ref();
    w->reset(wand, true, c2s);
}

MagicSplitter::~MagicSplitter()
{
    wizard->rem_ref();

    // release trackers
    for (unsigned i=0; i<wand.curse_tracker.size(); i++)
        delete wand.curse_tracker[i].tracker;
}

// FIXIT-M stop search on hit and failure (no possible match)
StreamSplitter::Status MagicSplitter::scan(
    Flow* f, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t*)
{
    Profile profile(wizPerfStats);
    count_scan(f);

    if ( wizard->cast_spell(wand, f, data, len) )
        count_hit(f);

    else if ( wizard->finished(wand) )
        return ABORT;

    // ostensibly continue but splitter will be swapped out upon hit
    return SEARCH;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

Wizard::Wizard(WizardModule* m)
{
    c2s_hexes = m->get_book(true, true);
    s2c_hexes = m->get_book(false, true);

    c2s_spells = m->get_book(true, false);
    s2c_spells = m->get_book(false, false);

    curses = m->get_curse_book();
}

Wizard::~Wizard()
{
    delete c2s_hexes;
    delete s2c_hexes;

    delete c2s_spells;
    delete s2c_spells;

    delete curses;
}

void Wizard::reset(Wand& w, bool tcp, bool c2s)
{
    if ( c2s )
    {
        w.hex = c2s_hexes->page1();
        w.spell = c2s_spells->page1();
    }
    else
    {
        w.hex = s2c_hexes->page1();
        w.spell = s2c_spells->page1();
    }

    if (w.curse_tracker.empty())
    {
        vector<const CurseDetails*> pages = curses->get_curses(tcp);
        for ( const CurseDetails* curse : pages )
        {
            if (tcp)
                w.curse_tracker.push_back({ curse, new CurseTracker });
            else
                w.curse_tracker.push_back({ curse, nullptr });
        }
    }
}

void Wizard::eval(Packet* p)
{
    Profile profile(wizPerfStats);

    if ( !p->is_udp() )
        return;

    if ( !p->data || !p->dsize )
        return;

    Wand wand;
    reset(wand, false, p->is_from_client());

    if ( cast_spell(wand, p->flow, p->data, p->dsize) )
        ++tstats.udp_hits;

    ++tstats.udp_scans;
}

StreamSplitter* Wizard::get_splitter(bool c2s)
{
    return new MagicSplitter(c2s, this);
}

bool Wizard::spellbind(
    const MagicPage*& m, Flow* f, const uint8_t* data, unsigned len)
{
    f->service = m->book.find_spell(data, len, m);

    if (f->service != nullptr)
    {
        // FIXIT-H need to make sure Flow's ipproto and service
        // correspond to HostApplicationEntry's ipproto and service
        host_cache_add_service(f->server_ip, f->ip_proto, f->server_port, f->service);
        return true;
    }

    return false;
}

bool Wizard::cursebind(vector<CurseServiceTracker>& curse_tracker, Flow* f,
        const uint8_t* data, unsigned len)
{
    for (const CurseServiceTracker& cst : curse_tracker)
    {
        if (cst.curse->alg(data, len, cst.tracker))
        {
            f->service = cst.curse->service.c_str();
            // FIXIT-H need to make sure Flow's ipproto and service
            // correspond to HostApplicationEntry's ipproto and service
            host_cache_add_service(f->server_ip, f->ip_proto, f->server_port, f->service);
            return true;
        }
    }

    return false;
}

bool Wizard::cast_spell(
    Wand& w, Flow* f, const uint8_t* data, unsigned len)
{
    if ( w.hex && spellbind(w.hex, f, data, len) )
        return true;

    if ( w.spell && spellbind(w.spell, f, data, len) )
        return true;

    if (cursebind(w.curse_tracker, f, data, len))
        return true;

    return false;
}

bool Wizard::finished(Wand& w)
{
    if ( w.hex or w.spell )
        return false;

    // FIXIT-L how to know curses are done?
    if ( !w.curse_tracker.empty() )
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new WizardModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* wiz_ctor(Module* m)
{
    WizardModule* mod = (WizardModule*)m;
    assert(mod);
    return new Wizard(mod);
}

static void wiz_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi wiz_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        WIZ_NAME,
        WIZ_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_WIZARD,
    PROTO_BIT__ANY_PDU,
    nullptr, // buffers
    nullptr, // service
    nullptr, // init
    nullptr, // term
    nullptr, // tinit
    nullptr, // tterm
    wiz_ctor,
    wiz_dtor,
    nullptr, // ssn
    nullptr  // reset
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

