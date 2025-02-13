//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_action.h"

#include "detection/detect.h"
#include "detection/treenodes.h"
#include "managers/action_manager.h"
#include "parser/parser.h"
#include "utils/stats.h"

#include "act_info.h"

using namespace snort;

namespace snort
{

std::string IpsAction::get_string(IpsAction::Type action)
{ return ActionManager::get_action_string(action); }

IpsAction::Type IpsAction::get_type(const char* s)
{ return ActionManager::get_action_type(s); }

IpsAction::Type IpsAction::get_max_types()
{ return ActionManager::get_max_action_types(); }

bool IpsAction::is_valid_action(IpsAction::Type action)
{
    if ( action < get_max_types() )
        return true;

    return false;
}

std::string IpsAction::get_default_priorities(bool alert_before_pass)
{ return ActionManager::get_action_priorities(alert_before_pass); }

bool IpsAction::log_it(const ActInfo& ai) const
{ return ai.log; }

uint64_t IpsAction::get_file_id(const ActInfo& ai) const
{ return ai.otn->sigInfo.file_id; }

void IpsAction::pass()
{
    pc.pass_pkts++;
}

void IpsAction::log(Packet* p, const ActInfo& ai)
{
    RuleTreeNode* rtn = getRtnFromOtn(ai.otn);

    if (!rtn)
        return;

    CallLogFuncs(p, ai.otn, rtn->listhead);
}

void IpsAction::alert(Packet* p, const ActInfo& ai)
{
    if (!ai.otn or !log_it(ai))
        return;

    RuleTreeNode* rtn = getRtnFromOtn(ai.otn);
    if (!rtn)
        return;

    /* Call OptTreeNode specific output functions */
    if (ai.otn->outputFuncs)
    {
        ListHead lh = { };  // FIXIT-L use of ListHead for CallLogFuncs() is a little unwieldy here
        lh.LogList = ai.otn->outputFuncs;
        CallLogFuncs(p, ai.otn, &lh);
    }
    CallAlertFuncs(p, ai.otn, rtn->listhead);
    CallLogFuncs(p, ai.otn, rtn->listhead);
}

} // snort

