//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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
**  @file       event_queue.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  @author     Marc Norton <mnorton@sourcefire.com>
**
**  @brief      Snort wrapper to sfeventq library.
**
**  These functions wrap the sfeventq API and provide the priority
**  functions for ordering incoming events.
**
** Notes:
**  11/1/05  Updates to add support for rules for all events in
**           decoders and preprocessors and the detection engine.
**           Added support for rule by rule flushing control via
**           metadata. Also added code to check for an otn for every
**           event (gid,sid pair).  This is now required to get events
**           to be logged. The decoders and preprocessors are still
**           configured independently, which allows them to inspect and
**           call the alerting functions DetectionEngine::queue_event. 
**
**           Any event that has no otn associated with it's gid,sid pair
**           will/should not alert, even if the preprocessor or decoder is
**           configured to detect an alertable event.
**
**           In the future, preporcessor may have an api that gets called
**           after rules are loaded that checks for the gid/sid -> otn
**           mapping, and then adjusts it's inspection or detection
**           accordingly.
**
**           DetectionEngine::queue_event() - only adds events that have an otn
**
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event_queue.h"

#include "detection/detection_engine.h"
#include "detection/fp_detect.h"
#include "filters/sfthreshold.h"
#include "log/messages.h"
#include "main/snort.h"
#include "parser/parser.h"
#include "utils/stats.h"
#include "utils/util.h"

#include "sfeventq.h"

//-------------------------------------------------

EventQueueConfig* EventQueueConfigNew()
{
    EventQueueConfig* eqc = (EventQueueConfig*)snort_calloc(sizeof(EventQueueConfig));

    eqc->max_events = 8;
    eqc->log_events = 3;

    eqc->order = SNORT_EVENTQ_CONTENT_LEN;
    eqc->process_all_events = 0;

    return eqc;
}

void EventQueueConfigFree(EventQueueConfig* eqc)
{
    if ( !eqc )
        return;

    snort_free(eqc);
}

