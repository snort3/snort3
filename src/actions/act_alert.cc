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
// act_alert.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_action.h"
#include "framework/module.h"
#include "protocols/packet.h"

#include "actions_module.h"

using namespace snort;

#define action_name "alert"
#define action_help \
    "generate alert on the current packet"

#define module_name "alert"
#define module_help \
    "manage the counters for the alert action"

static THREAD_LOCAL struct AlertStats
{
    PegCount alert;
} alert_stats;

const PegInfo alert_pegs[] =
{
    { CountType::SUM, "alert", "number of packets that matched an IPS alert rule" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
class AlertAction : public IpsAction
{
public:
    AlertAction() : IpsAction(action_name, nullptr) { }

    void exec(Packet*, const ActInfo&) override;
};

void AlertAction::exec(Packet* p, const ActInfo& ai)
{
    alert(p, ai);
    ++alert_stats.alert;
}

//-------------------------------------------------------------------------
class AlertActionModule : public Module
{
public:
    AlertActionModule() : Module(module_name, module_help)
    { ActionsModule::add_action(module_name, alert_pegs); }

    bool stats_are_aggregated() const override
    { return true; }

    void show_stats() override
    { /* These stats are shown by ActionsModule. */ }

    const PegInfo* get_pegs() const override
    { return alert_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&alert_stats; }
};

//-------------------------------------------------------------------------
static Module* mod_ctor()
{ return new AlertActionModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsAction* alert_ctor(Module*)
{ return new AlertAction; }

static void alert_dtor(IpsAction* p)
{ delete p; }

static ActionApi alert_api
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
    IpsAction::IAP_ALERT,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    alert_ctor,
    alert_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* act_alert[] =
#endif
{
    &alert_api.base,
    nullptr
};

