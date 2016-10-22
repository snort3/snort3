//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event_wrapper.h"

#include "detection/fp_detect.h"
#include "parser/parser.h"

/*
 * This function has been updated to find an otn and route the call to fpLogEvent
 * if possible.  This requires a rule be written for each decoder event,
 * and possibly some preporcessor events.  The bulk of eventing is handled vie the
 * DetectionEngine::queue_event() and SnortEventLog() functions - whichalready
 * route the events to the fpLogEvent()function.
 */
uint32_t GenerateSnortEvent(Packet* p, uint32_t gid, uint32_t sid)
{
    OptTreeNode* otn = GetOTN(gid, sid);

    if ( !otn )
        return 0;

    RuleTreeNode* rtn = getRuntimeRtnFromOtn(otn);

    if ( !rtn )
        return 0;

    fpLogEvent(rtn, otn, p);

    return 0;  //otn->event_data.event_id; // FIXIT-M EVENT
}

