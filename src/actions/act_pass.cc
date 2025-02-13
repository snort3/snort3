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
// act_pass.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "framework/ips_action.h"
#include "framework/module.h"
#include "protocols/packet.h"

#include "actions_module.h"

using namespace snort;

#define action_name "pass"
#define action_help \
    "mark the current packet as passed"

#define module_name "pass"
#define module_help \
    "manage the counters for the pass action"

static THREAD_LOCAL struct PassStats
{
    PegCount pass;
} pass_stats;

const PegInfo pass_pegs[] =
{
    { CountType::SUM, "pass", "number of packets that matched an IPS pass rule" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
class PassAction : public IpsAction
{
public:
    PassAction() : IpsAction(action_name, nullptr) { }

    void exec(Packet*, const ActInfo&) override;
};

void PassAction::exec(Packet* p, const ActInfo& ai)
{
    if ( log_it(ai) )
    {
        pass();
        p->packet_flags |= PKT_PASS_RULE;
        ++pass_stats.pass;
    }
}

//-------------------------------------------------------------------------

class PassActionModule : public Module
{
public:
    PassActionModule() : Module(module_name, module_help)
    { ActionsModule::add_action(module_name, pass_pegs); }

    bool stats_are_aggregated() const override
    { return true; }

    void show_stats() override
    { /* These stats are shown by ActionsModule. */ }

    const PegInfo* get_pegs() const override
    { return pass_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&pass_stats; }
};

//-------------------------------------------------------------------------
static Module* mod_ctor()
{ return new PassActionModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsAction* pass_ctor(Module*)
{ return new PassAction; }

static void pass_dtor(IpsAction* p)
{ delete p; }

static ActionApi pass_api
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
    IpsAction::IAP_PASS,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    pass_ctor,
    pass_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* act_pass[] =
#endif
{
    &pass_api.base,
    nullptr
};

