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
// act_replace.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "actions/actions_module.h"
#include "detection/detection_engine.h"
#include "framework/ips_action.h"
#include "framework/module.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

using namespace snort;

#define action_name "rewrite"
#define action_help \
    "overwrite packet contents with the \"replace\" option content"

#define module_name "rewrite"
#define module_help \
    "manage the counters for the rewrite action"

static THREAD_LOCAL struct ReplaceStats
{
    PegCount replace;
} replace_stats;

const PegInfo replace_pegs[] =
{
    { CountType::SUM, "rewrite", "number of packets that matched an IPS rewrite rule" },
    { CountType::END, nullptr, nullptr }
};

//--------------------------------------------------------------------------
// queue foo
//--------------------------------------------------------------------------

static inline void Replace_ApplyChange(Packet* p, std::string& data, unsigned offset)
{
    uint8_t* start = const_cast<uint8_t*>(p->data) + offset;
    const uint8_t* end = p->data + p->dsize;
    unsigned len;

    if ( (start + data.size()) >= end )
        len = p->dsize - offset;
    else
        len = data.size();

    memcpy(start, data.c_str(), len);
}

static void Replace_ModifyPacket(Packet* p)
{
    std::string data;
    unsigned offset;
    bool modified = false;

    while ( DetectionEngine::get_replacement(data, offset) )
    {
        modified = true;
        Replace_ApplyChange(p, data, offset);
    }

    if ( modified )
        p->packet_flags |= PKT_MODIFIED;

    DetectionEngine::clear_replacement();
}

//-------------------------------------------------------------------------
// active action
//-------------------------------------------------------------------------
class ReplaceActiveAction : public ActiveAction
{
public:
    ReplaceActiveAction() : ActiveAction(ActionPriority::AP_MODIFY) { }
    void delayed_exec(Packet*) override;
};

void ReplaceActiveAction::delayed_exec(Packet* p)
{
    if ( p->is_rebuilt() )
        return;

    Replace_ModifyPacket(p);
}

//-------------------------------------------------------------------------
// ips action
//-------------------------------------------------------------------------
class ReplaceAction : public IpsAction
{
public:
    ReplaceAction() : IpsAction(action_name, &rep_act_action) { }

    void exec(Packet*, const ActInfo&) override;

private:
    ReplaceActiveAction rep_act_action;
};

void ReplaceAction::exec(Packet* p, const ActInfo& ai)
{
    p->active->rewrite_packet(p);

    alert(p, ai);
    ++replace_stats.replace;
}

//-------------------------------------------------------------------------

class ReplaceActionModule : public Module
{
public:
    ReplaceActionModule() : Module(module_name, module_help)
    { ActionsModule::add_action(module_name, replace_pegs); }

    bool stats_are_aggregated() const override
    { return true; }

    void show_stats() override
    { /* These stats are shown by ActionsModule. */ }

    const PegInfo* get_pegs() const override
    { return replace_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&replace_stats; }
};

//-------------------------------------------------------------------------
static Module* mod_ctor()
{ return new ReplaceActionModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsAction* rep_ctor(Module*)
{ return new ReplaceAction; }

static void rep_dtor(IpsAction* p)
{ delete p; }

static ActionApi rep_api
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        action_name,
        action_help,
        mod_ctor,
        mod_dtor,
    },
    IpsAction::IAP_REWRITE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    rep_ctor,
    rep_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* act_replace[] =
#endif
{
    &rep_api.base,
    nullptr
};

