//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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
// act_drop.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_action.h"
#include "framework/module.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

#include "actions_module.h"

using namespace snort;

#define action_name "drop"
#define action_help \
    "drop the current packet"

#define module_name "drop"
#define module_help \
    "manage the counters for the drop action"

static THREAD_LOCAL struct DropStats
{
    PegCount drop;
} drop_stats;

const PegInfo drop_pegs[] =
{
    { CountType::SUM, "drop", "number of packets that matched an IPS drop rule" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
class DropAction : public IpsAction
{
public:
    DropAction() : IpsAction(action_name, nullptr) { }

    void exec(Packet*, const ActInfo&) override;
    bool drops_traffic() override { return true; }
};

void DropAction::exec(Packet* p, const ActInfo& ai)
{
    p->active->drop_packet(p);
    p->active->set_drop_reason("ips");

    alert(p, ai);
    ++drop_stats.drop;
}

//-------------------------------------------------------------------------
class DropActionModule : public Module
{
public:
    DropActionModule() : Module(module_name, module_help)
    { ActionsModule::add_action(module_name, drop_pegs); }

    bool stats_are_aggregated() const override
    { return true; }

    void show_stats() override
    { /* These stats are shown by ActionsModule. */ }

    const PegInfo* get_pegs() const override
    { return drop_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&drop_stats; }
};

//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new DropActionModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsAction* drop_ctor(Module*)
{ return new DropAction; }

static void drop_dtor(IpsAction* p)
{ delete p; }

static ActionApi drop_api
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
    IpsAction::IAP_DROP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    drop_ctor,
    drop_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* act_drop[] =
#endif
{
    &drop_api.base,
    nullptr
};

