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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "actions.h"

#include "detection/detect.h"
#include "detection/tag.h"
#include "packet_io/active.h"
#include "parser/parser.h"
#include "utils/stats.h"

using namespace snort;

static void pass()
{
    pc.pass_pkts++;
}

static void log(Packet* p, const OptTreeNode* otn)
{
    RuleTreeNode* rtn = getRuntimeRtnFromOtn(otn);
    CallLogFuncs(p, otn, rtn->listhead);
}

static void alert(Packet* p, const OptTreeNode* otn)
{
    RuleTreeNode* rtn = getRuntimeRtnFromOtn(otn);

    if (rtn == nullptr)
        return;

    /* Call OptTreeNode specific output functions */
    if (otn->outputFuncs)
    {
        ListHead lh;  // FIXIT-L use of ListHead for CallLogFuncs() is a little unwieldy here
        lh.LogList = otn->outputFuncs;
        CallLogFuncs(p, otn, &lh);
    }
    CallAlertFuncs(p, otn, rtn->listhead);
    CallLogFuncs(p, otn, rtn->listhead);
}

static const char* const type[Actions::MAX] =
{
    "none", "log", "pass", "alert", "drop", "block", "reset"
};

const char* Actions::get_string(Actions::Type action)
{
    if ( action < Actions::MAX )
        return type[action];

    return "ERROR";
}

Actions::Type Actions::get_type(const char* s)
{
    if ( !s )
        return Actions::NONE;

    else if ( !strcasecmp(s, Actions::get_string(Actions::LOG)) )
        return Actions::LOG;

    else if ( !strcasecmp(s, Actions::get_string(Actions::PASS)) )
        return Actions::PASS;

    else if ( !strcasecmp(s, Actions::get_string(Actions::ALERT)) )
        return Actions::ALERT;

    else if ( !strcasecmp(s, Actions::get_string(Actions::DROP)) )
        return Actions::DROP;

    else if ( !strcasecmp(s, Actions::get_string(Actions::BLOCK)) )
        return Actions::BLOCK;

    else if ( !strcasecmp(s, Actions::get_string(Actions::RESET)) )
        return Actions::RESET;

    return Actions::NONE;
}

void Actions::execute(Actions::Type action, Packet* p, const OptTreeNode* otn,
    uint16_t event_id)
{
    switch (action)
    {
    case Actions::PASS:
        pass();
        SetTags(p, otn, event_id);
        break;

    case Actions::ALERT:
        alert(p, otn);
        SetTags(p, otn, event_id);
        break;

    case Actions::LOG:
        log(p, otn);
        SetTags(p, otn, event_id);
        break;

    case Actions::DROP:
        Active::drop_packet(p);
        alert(p, otn);
        SetTags(p, otn, event_id);
        break;

    case Actions::BLOCK:
        Active::block_session(p);
        alert(p, otn);
        SetTags(p, otn, event_id);
        break;

    case Actions::RESET:
        Active::reset_session(p);
        alert(p, otn);
        SetTags(p, otn, event_id);
        break;

    default:
        break;
    }
}

void Actions::apply(Actions::Type action, Packet* p)
{
    switch ( action )
    {
    case Actions::DROP:
        Active::drop_packet(p);
        break;

    case Actions::BLOCK:
        Active::block_session(p);
        break;

    case Actions::RESET:
        Active::reset_session(p);
        break;

    default:
        break;
    }
}

