//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// act_file_id.cc author Bhargava Jandhyala <bjandhya@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_api/file_flows.h"
#include "file_api/file_lib.h"
#include "framework/ips_action.h"
#include "managers/action_manager.h"
#include "parser/parser.h"

#include "actions_module.h"

using namespace snort;

#define action_name "file_id"
#define action_help \
    "file_id file type id"

#define module_name "file_id_action"
#define module_help \
    "manage the counters for the file_id action"

static THREAD_LOCAL struct File_IdStats
{
    PegCount file_id;
} file_id_stats;

const PegInfo file_id_pegs[] =
{
    { CountType::SUM, "file_id", "number of packets that matched an IPS file_id rule" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// ips action
//-------------------------------------------------------------------------

class File_IdAction : public IpsAction
{
public:
    File_IdAction() : IpsAction(action_name, nullptr) { }
    void exec(Packet*, const ActInfo&) override;
};

void File_IdAction::exec(Packet* p, const ActInfo& ai)
{
    if (!p->flow)
      return;

    FileFlows* files = FileFlows::get_file_flows(p->flow, false);

    if (!files)
        return;

    FileContext* file = files->get_current_file_context();

    if (!file)
        return;

    file->set_file_type(get_file_id(ai));
    ++file_id_stats.file_id;
}

//-------------------------------------------------------------------------

class File_IdActionModule : public Module
{
public:
    File_IdActionModule() : Module(module_name, module_help)
    { ActionsModule::add_action(module_name, file_id_pegs); }

    bool stats_are_aggregated() const override
    { return true; }

    void show_stats() override
    { /* These stats are shown by ActionsModule. */ }

    const PegInfo* get_pegs() const override
    { return file_id_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&file_id_stats; }
};

//-------------------------------------------------------------------------
static Module* mod_ctor()
{ return new File_IdActionModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsAction* file_id_ctor(Module*)
{ return new File_IdAction; }

static void file_id_dtor(IpsAction* p)
{ delete p; }

static ActionApi file_id_api
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
    IpsAction::IAP_OTHER,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    file_id_ctor,
    file_id_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* act_file_id[] =
#endif
{
    &file_id_api.base,
    nullptr
};

