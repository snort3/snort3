//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
/**
 * @file   event_wrapper.c
 * @author Chris Green <cmg@sourcefire.com>
 *
 * @date   Wed Jun 18 10:49:59 2003
 *
 * @brief  generate a snort event
 *
 * This is a wrapper around SetEvent,CallLogFuncs,CallEventFuncs
 *
 * Notes:
 *
 *   10/31/05 - Marc Norton
 *   Changes to support every event being controlled via a rule.
 *   Modified GenerateSnortEvent() to re-route events to 'fpLogEvent'
 *   if a suitable otn was found.  If no otn was found, than we do
 *   not log the event at all, as no rule was provided.
 *   Preprocessors are configured independently, and may detect
 *   an event, but the rule controls the alert/drop functionality.
 */

#include "event_wrapper.h"

#include "detection/rules.h"
#include "detection/treenodes.h"
#include "detection/signature.h"
#include "detection/fp_detect.h"
#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "parser/parser.h"
#include "events/event.h"
#include "detection/detect.h"
#include "utils/util.h"

/*
 * This function has been updated to find an otn and route the call to fpLogEvent
 * if possible.  This requires a rule be written for each decoder event,
 * and possibly some preporcessor events.  The bulk of eventing is handled vie the
 * SnortEventqAdd() and SnortEventLog() functions - whichalready  route the events to
 * the fpLogEvent()function.
 */
uint32_t GenerateSnortEvent(Packet* p, uint32_t gid, uint32_t sid)
{
    OptTreeNode* otn;
    RuleTreeNode* rtn;

    otn = GetOTN(gid, sid);

    if (otn == NULL)
        return 0;

    rtn = getRuntimeRtnFromOtn(otn);

    if (rtn == NULL)
        return 0;

    fpLogEvent(rtn, otn, p);

    return 0;  //otn->event_data.event_id; // FIXIT-M EVENT
}

/**
 * Log additional packet data using the same kinda mechanism tagging does.
 *
 * @param p Packet to log
 * @param gen_id generator id
 * @param sig_id signature id
 * @param sig_rev revision is
 * @param classification classification id
 * @param priority priority level
 * @param event_ref reference of a previous event
 * @param ref_sec the tv_sec of that previous event
 * @param msg The message data txt
 *
 * @return 1 on success, 0 on FAILURE ( note this is to stay the same as GenerateSnortEvent() )
 */
int LogTagData(Packet* p,
    uint32_t gen_id,
    uint32_t sig_id,
    uint32_t sig_rev,
    uint32_t classification,
    uint32_t priority,
    uint32_t event_ref,
    time_t ref_sec,
    char* msg)
{
    Event event;

    if (!event_ref || !ref_sec)
        return 0;

    SetEvent(&event, gen_id, sig_id, sig_rev, classification, priority, event_ref);

    event.ref_time.tv_sec = (uint32_t)ref_sec;

    if (p)
        CallLogFuncs(p, NULL, &event, msg);

    return 1;
}

