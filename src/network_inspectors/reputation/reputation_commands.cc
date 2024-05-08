//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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
// reputation_commands.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "reputation_commands.h"

#include "control/control.h"
#include "framework/pig_pen.h"
#include "log/messages.h"
#include "main/analyzer_command.h"
#include "main/snort_config.h"

#include "reputation_common.h"
#include "reputation_inspect.h"

using namespace snort;

class ReputationReload : public AnalyzerCommand
{
public:
    ReputationReload(ControlConn*, Reputation&);
    ~ReputationReload() override;

    bool execute(Analyzer&, void**) override;
    bool need_update_reload_id() const override
    { return true; }

    const char* stringify() override
    { return "REPUTATION_RELOAD"; }

protected:
    Reputation& ins;
    ReputationData* data;
};

ReputationReload::ReputationReload(ControlConn* conn, Reputation& ins)
    : AnalyzerCommand(conn), ins(ins)
{
    ins.add_global_ref();
    log_message(".. reputation reloading\n");
    data = ins.load_data();
}

ReputationReload::~ReputationReload()
{
    ins.swap_data(data);
    log_message("== Reputation reload complete\n");
    ins.rem_global_ref();
}

bool ReputationReload::execute(Analyzer&, void**)
{
    ins.swap_thread_data(data);
    return true;
}

static int reload(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    Reputation* ins = static_cast<Reputation*>(PigPen::get_inspector(REPUTATION_NAME));

    if (ins)
        main_broadcast_command(new ReputationReload(ctrlcon, *ins), ctrlcon);
    else
        AnalyzerCommand::log_message(ctrlcon, "No reputation instance configured to reload\n");
    return 0;
}

const Command reputation_cmds[] =
{
    {"reload", reload, nullptr, "reload reputation data"},
    {nullptr, nullptr, nullptr, nullptr}
};
