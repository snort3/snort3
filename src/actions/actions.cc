//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

    if (rtn == NULL)
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

static const char* const rule_type[RULE_TYPE__MAX] =
{
    "none", "log", "pass", "alert", "drop", "block", "reset"
};

const char* get_action_string(RuleType action)
{
    if ( action < RULE_TYPE__MAX )
        return rule_type[action];

    return "ERROR";
}

RuleType get_action_type(const char* s)
{
    if ( !s )
        return RULE_TYPE__NONE;

    else if ( !strcasecmp(s, ACTION_LOG) )
        return RULE_TYPE__LOG;

    else if ( !strcasecmp(s, ACTION_PASS) )
        return RULE_TYPE__PASS;

    else if ( !strcasecmp(s, ACTION_ALERT) )
        return RULE_TYPE__ALERT;

    else if ( !strcasecmp(s, ACTION_DROP) )
        return RULE_TYPE__DROP;

    else if ( !strcasecmp(s, ACTION_BLOCK) )
        return RULE_TYPE__BLOCK;

    else if ( !strcasecmp(s, ACTION_RESET) )
        return RULE_TYPE__RESET;

    return RULE_TYPE__NONE;
}

void action_execute(RuleType action, Packet* p, const OptTreeNode* otn,
    uint16_t event_id)
{
    switch (action)
    {
    case RULE_TYPE__PASS:
        pass();
        SetTags(p, otn, event_id);
        break;

    case RULE_TYPE__ALERT:
        alert(p, otn);
        SetTags(p, otn, event_id);
        break;

    case RULE_TYPE__LOG:
        log(p, otn);
        SetTags(p, otn, event_id);
        break;

    case RULE_TYPE__DROP:
        Active::drop_packet(p);
        alert(p, otn);
        SetTags(p, otn, event_id);
        break;

    case RULE_TYPE__BLOCK:
        Active::block_session(p);
        alert(p, otn);
        SetTags(p, otn, event_id);
        break;

    case RULE_TYPE__RESET:
        Active::reset_session(p);
        alert(p, otn);
        SetTags(p, otn, event_id);
        break;

    default:
        break;
    }
}

void action_apply(RuleType action, Packet* p)
{
    switch ( action )
    {
    case RULE_TYPE__DROP:
        Active::drop_packet(p);
        break;

    case RULE_TYPE__BLOCK:
        Active::block_session(p);
        break;

    case RULE_TYPE__RESET:
        Active::reset_session(p);
        break;

    default:
        break;
    }
}

