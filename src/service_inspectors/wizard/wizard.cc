//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/flow.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "stream/stream_splitter.h"
#include "trace/trace_api.h"

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
    PegCount tcp_misses;
    PegCount udp_scans;
    PegCount udp_hits;
    PegCount udp_misses;
    PegCount user_scans;
    PegCount user_hits;
    PegCount user_misses;
};

const PegInfo wiz_pegs[] =
{
    { CountType::SUM, "tcp_scans", "tcp payload scans" },
    { CountType::SUM, "tcp_hits", "tcp identifications" },
    { CountType::SUM, "tcp_misses", "tcp searches abandoned" },
    { CountType::SUM, "udp_scans", "udp payload scans" },
    { CountType::SUM, "udp_hits", "udp identifications" },
    { CountType::SUM, "udp_misses", "udp searches abandoned" },
    { CountType::SUM, "user_scans", "user payload scans" },
    { CountType::SUM, "user_hits", "user identifications" },
    { CountType::SUM, "user_misses", "user searches abandoned" },
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
    const MagicPage* bookmark;
    vector<CurseServiceTracker> curse_tracker;
};

class Wizard;

class MagicSplitter : public StreamSplitter
{
public:
    MagicSplitter(bool, class Wizard*);
    ~MagicSplitter() override;

    Status scan(Packet*, const uint8_t* data, uint32_t len,
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

    void count_miss(const Flow* f)
    {
        if ( f->pkt_type == PktType::TCP )
            ++tstats.tcp_misses;
        else
            ++tstats.user_misses;
    }

private:
    Wizard* wizard;
    Wand wand;
    uint16_t wizard_processed_bytes;
};

class Wizard : public Inspector
{
public:
    Wizard(WizardModule*);
    ~Wizard() override;

    void eval(Packet*) override;

    StreamSplitter* get_splitter(bool) override;

    inline bool finished(Wand& w)
    { return !w.hex and !w.spell and w.curse_tracker.empty(); }

    void reset(Wand&, bool, MagicBook::MagicBook::ArcaneType);

    bool cast_spell(Wand&, Flow*, const uint8_t*, unsigned, uint16_t&);
    bool spellbind(const MagicPage*&, Flow*, const uint8_t*, unsigned, const MagicPage*&);
    bool cursebind(const vector<CurseServiceTracker>&, Flow*, const uint8_t*, unsigned);

public:
    MagicBook* c2s_hexes;
    MagicBook* s2c_hexes;

    MagicBook* c2s_spells;
    MagicBook* s2c_spells;

    CurseBook* curses;

    uint16_t max_search_depth;
};

//-------------------------------------------------------------------------
// splitter - this doesn't actually split the stream but it applies
// basic magic type logic to determine the appropriate inspector that
// will split the stream.
//-------------------------------------------------------------------------

MagicSplitter::MagicSplitter(bool c2s, class Wizard* w) :
    StreamSplitter(c2s), wizard_processed_bytes(0)
{
    wizard = w;
    w->add_ref();
    // Used only in case of TCP traffic
    w->reset(wand, c2s, MagicBook::ArcaneType::TCP);
}

MagicSplitter::~MagicSplitter()
{
    wizard->rem_ref();

    // release trackers
    for ( unsigned i = 0; i < wand.curse_tracker.size(); i++ )
        delete wand.curse_tracker[i].tracker;
}

StreamSplitter::Status MagicSplitter::scan(
    Packet* pkt, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t*)
{
    Profile profile(wizPerfStats);
    count_scan(pkt->flow);

    bytes_scanned += len;

    if ( wizard->cast_spell(wand, pkt->flow, data, len, wizard_processed_bytes) )
    {
        trace_logf(wizard_trace, pkt, "%s streaming search found service %s\n",
            to_server() ? "c2s" : "s2c", pkt->flow->service);
        count_hit(pkt->flow);
        wizard_processed_bytes = 0;

        return STOP;
    }
    else if ( wizard->finished(wand) or bytes_scanned >= max(pkt->flow) )
    {
        count_miss(pkt->flow);
        trace_logf(wizard_trace, pkt, "%s streaming search abandoned\n", to_server() ? "c2s" : "s2c");
        wizard_processed_bytes = 0;

        if ( !pkt->flow->flags.svc_event_generated )
        {
            DataBus::publish(FLOW_NO_SERVICE_EVENT, pkt);
            pkt->flow->flags.svc_event_generated = true;
        }

        return ABORT;
    }

    // FIXIT-L Ideally, this event should be raised after wizard aborts its search. However, this
    // could take multiple packets because wizard needs wizard.max_search_depth payload bytes before
    // it aborts. This is an issue for AppId which consumes this event. AppId is required to declare
    // unknown service as soon as it can so that the flow actions (such as IPS block, etc) don't get
    // delayed. Because AppId depends on wizard only for SSH detection and SSH inspector can be
    // attached very early, event is raised here after first scan. In the future, wizard should be
    // enhanced to abort sooner if it can't detect service.
    if ( !pkt->flow->service and !pkt->flow->flags.svc_event_generated )
    {
        DataBus::publish(FLOW_NO_SERVICE_EVENT, pkt);
        pkt->flow->flags.svc_event_generated = true;
    }

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
    max_search_depth = m->get_max_search_depth();
}

Wizard::~Wizard()
{
    delete c2s_hexes;
    delete s2c_hexes;

    delete c2s_spells;
    delete s2c_spells;

    delete curses;
}

void Wizard::reset(Wand& w, bool c2s, MagicBook::ArcaneType proto)
{
    w.bookmark = nullptr;

    if ( c2s )
    {
        w.hex = c2s_hexes->page1(proto);
        w.spell = c2s_spells->page1(proto);
    }
    else
    {
        w.hex = s2c_hexes->page1(proto);
        w.spell = s2c_spells->page1(proto);
    }

    bool tcp = MagicBook::ArcaneType::TCP == proto;

    if ( w.curse_tracker.empty() )
    {
        for ( const CurseDetails* curse : curses->get_curses(tcp) )
        {
            if ( tcp )
                w.curse_tracker.emplace_back( CurseServiceTracker{ curse, new CurseTracker } );
            else
                w.curse_tracker.emplace_back( CurseServiceTracker{ curse, nullptr } );
        }
    }
}

void Wizard::eval(Packet* p)
{
    Profile profile(wizPerfStats);

    if ( !p->is_udp() )
        return;

    if ( !p->data or !p->dsize )
        return;

    bool c2s = p->is_from_client();
    Wand wand;
    reset(wand, c2s, MagicBook::ArcaneType::UDP);
    uint16_t udp_processed_bytes = 0;

    ++tstats.udp_scans;

    if ( cast_spell(wand, p->flow, p->data, p->dsize, udp_processed_bytes) )
    {
        trace_logf(wizard_trace, p, "%s datagram search found service %s\n",
            c2s ? "c2s" : "s2c", p->flow->service);
        ++tstats.udp_hits;
    }
    else
    {
        p->flow->clear_clouseau();
        trace_logf(wizard_trace, p, "%s datagram search abandoned\n", c2s ? "c2s" : "s2c");
        ++tstats.udp_misses;
    }
}

StreamSplitter* Wizard::get_splitter(bool c2s)
{
    return new MagicSplitter(c2s, this);
}

bool Wizard::spellbind(
    const MagicPage*& m, Flow* f, const uint8_t* data, unsigned len, const MagicPage*& bookmark)
{
    f->service = m->book.find_spell(data, len, m, bookmark);

    return f->service != nullptr;
}

bool Wizard::cursebind(const vector<CurseServiceTracker>& curse_tracker, Flow* f,
        const uint8_t* data, unsigned len)
{
    for ( const CurseServiceTracker& cst : curse_tracker )
    {
        if ( cst.curse->alg(data, len, cst.tracker) )
        {
            f->service = cst.curse->service;

            if ( f->service )
                return true;
        }
    }

    return false;
}

bool Wizard::cast_spell(
    Wand& w, Flow* f, const uint8_t* data, unsigned len, uint16_t& wizard_processed_bytes)
{
    auto curse_len = len;
    len = std::min(len, static_cast<unsigned>(max_search_depth - wizard_processed_bytes));
    wizard_processed_bytes += len;

    if ( w.hex and spellbind(w.hex, f, data, len, w.bookmark) )
        return true;

    if ( w.spell and spellbind(w.spell, f, data, len, w.bookmark) )
        return true;

    if ( cursebind(w.curse_tracker, f, data, curse_len) )
        return true;

    // If we reach max value of wizard_processed_bytes,
    // but not assign any inspector - raise tcp_miss and stop
    if ( !f->service and wizard_processed_bytes >= max_search_depth )
    {
        w.spell = nullptr;
        w.hex = nullptr;

        for ( const CurseServiceTracker& cst : w.curse_tracker )
            delete cst.tracker;

        w.curse_tracker.clear();
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

