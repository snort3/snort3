//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "actions/actions.h"
#include "snort.h"
#include "snort_types.h"
#include "snort_debug.h"
#include "util.h"
#include "obfuscation.h"
#include "signature.h"
#include "stream/stream_api.h"
#include "packet_io/active.h"
#include "detection/detect.h"
#include "detection_util.h"
#include "detection/tag.h"

static int PassAction(void)
{
    pc.pass_pkts++;

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   => Pass rule, returning...\n"););
    return 1;
}

int AlertAction(Packet* p, const OptTreeNode* otn)
{
    RuleTreeNode *rtn = getRuntimeRtnFromOtn(otn);

    if (rtn == NULL)
        return 0;

    /* Call OptTreeNode specific output functions */
    if(otn->outputFuncs)
    {
        ListHead lh;  // FIXIT-L "kinda hackish"
        lh.LogList = otn->outputFuncs;
        CallLogFuncs(p, otn, &lh);
    }
    CallAlertFuncs(p, otn, rtn->listhead);

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   => Finishing alert packet!\n"););

    CallLogFuncs(p, otn, rtn->listhead);

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   => Alert packet finished, returning!\n"););

    return 1;
}

static int DropAction(Packet* p, const OptTreeNode* otn)
{
    RuleTreeNode *rtn = getRuntimeRtnFromOtn(otn);

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
               "        <!!> Generating Alert and dropping! \"%s\"\n",
               otn->sigInfo.message););

    /*
    **  Set packet flag so output plugins will know we dropped the
    **  packet we just logged.
    */
    Active_DropSession(p);

    CallAlertFuncs(p, otn, rtn->listhead);

    CallLogFuncs(p, otn, rtn->listhead);

    return 1;
}

static int SDropAction(Packet* p, const OptTreeNode* otn)
{
#ifdef DEBUG_MSGS
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
               "        <!!> Dropping without Alerting! \"%s\"\n",
               otn->sigInfo.message););

    // Let's silently drop the packet
    Active_DropSession(p);
#else
    UNUSED(otn);
    UNUSED(p);
#endif
    return 1;
}

static int LogAction(Packet* p, const OptTreeNode* otn)
{
    RuleTreeNode *rtn = getRuntimeRtnFromOtn(otn);

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   => Logging packet data and returning...\n"););

    CallLogFuncs(p, otn, rtn->listhead);

#ifdef BENCHMARK
    printf("        <!!> Check count = %d\n", check_count);
    check_count = 0;
    printf(" **** cmpcount: %d **** \n", cmpcount);
#endif

    return 1;
}

static const char* const rule_type[RULE_TYPE__MAX] =
{
    "none", "alert", "drop", 
    "log", "pass", "sdrop"
};

const char* get_action_string(int action)
{
    if ( action < RULE_TYPE__MAX )
        return rule_type[action];
    
    return "ERROR";
}

RuleType get_action_type(const char* s)
{
    if (s == NULL)
        return RULE_TYPE__NONE;

    if ( !strcasecmp(s, ACTION_ALERT) )
        return RULE_TYPE__ALERT;

    else if ( !strcasecmp(s, ACTION_DROP) )
        return RULE_TYPE__DROP;

    else if ( !strcasecmp(s, ACTION_BLOCK) )
        return RULE_TYPE__DROP;

    else if ( !strcasecmp(s, ACTION_LOG) )
        return RULE_TYPE__LOG;

    else if ( !strcasecmp(s, ACTION_PASS) )
        return RULE_TYPE__PASS;

    else if ( !strcasecmp(s, ACTION_SDROP) )
        return RULE_TYPE__SDROP;

    else if ( !strcasecmp(s, ACTION_SBLOCK) )
        return RULE_TYPE__SDROP;

    return RULE_TYPE__NONE;
}

void action_execute(int action, Packet* p, OptTreeNode* otn, uint16_t event_id)
{
    switch (action)
    {
        case RULE_TYPE__PASS:
            SetTags(p, otn, event_id);
            PassAction();
            break;

        case RULE_TYPE__ALERT:
            AlertAction(p, otn);
            SetTags(p, otn, event_id);
            break;

        case RULE_TYPE__LOG:
            LogAction(p, otn);
            SetTags(p, otn, event_id);
            break;

        case RULE_TYPE__DROP:
            DropAction(p, otn);
            SetTags(p, otn, event_id);
            break;

        case RULE_TYPE__SDROP:
            SDropAction(p, otn);
            break;

        default:
            break;
    }
}

