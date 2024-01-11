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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "actions.h"

#include "detection/detect.h"
#include "managers/action_manager.h"
#include "parser/parser.h"
#include "utils/stats.h"

using namespace snort;

void Actions::pass()
{
    pc.pass_pkts++;
}

void Actions::log(Packet* p, const OptTreeNode* otn)
{
    RuleTreeNode* rtn = getRtnFromOtn(otn);
    if (!rtn)
        return;

    CallLogFuncs(p, otn, rtn->listhead);
}

void Actions::alert(Packet* p, const OptTreeNode* otn)
{
    if (!otn)
        return;

    RuleTreeNode* rtn = getRtnFromOtn(otn);
    if (!rtn)
        return;

    /* Call OptTreeNode specific output functions */
    if (otn->outputFuncs)
    {
        ListHead lh = {};  // FIXIT-L use of ListHead for CallLogFuncs() is a little unwieldy here
        lh.LogList = otn->outputFuncs;
        CallLogFuncs(p, otn, &lh);
    }
    CallAlertFuncs(p, otn, rtn->listhead);
    CallLogFuncs(p, otn, rtn->listhead);
}

std::string Actions::get_string(Actions::Type action)
{
    return ActionManager::get_action_string(action);
}

Actions::Type Actions::get_type(const char* s)
{
    return ActionManager::get_action_type(s);
}

Actions::Type Actions::get_max_types()
{
    return ActionManager::get_max_action_types();
}

bool Actions::is_valid_action(Actions::Type action)
{
    if ( action < get_max_types() )
        return true;

    return false;
}

std::string Actions::get_default_priorities(bool alert_before_pass)
{
    return ActionManager::get_action_priorities(alert_before_pass);
}
