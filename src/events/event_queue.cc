//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
**           metadata. Also added code to check fo an otn for every
**           event (gid,sid pair).  This is now required to get events
**           to be logged. The decoders and preprocessors are still
**           configured independently, which allows them to inspect and
**           call the alerting functions SnortEventqAdd, GenerateSnortEvent()
**           and GenerateEvent2() for portscan.cc.  The GenerateSnortEvent()
**           function now finds and otn and calls fpLogEvent.
**
**           Any event that has no otn associated with it's gid,sid pair,
**           will/should not alert, even if the preprocessor or decoiderr is
**           configured to detect an alertable event.
**
**           In the future, preporcessor may have an api that gets called
**           after rules are loaded that checks for the gid/sid -> otn
**           mapping, and then adjusts it's inspection or detection
**           accordingly.
**
**           SnortEventqAdd() - only adds events that have an otn
**
*/
#include "event_queue.h"

#include "sfeventq.h"
#include "event_wrapper.h"
#include "detection/fp_detect.h"
#include "utils/util.h"
#include "utils/stats.h"
#include "filters/sfthreshold.h"
#include "parser/parser.h"

typedef struct s_SNORT_EVENTQ_USER
{
    void* pkt;
} SNORT_EVENTQ_USER;

#define NUM_EVENT_QUEUES 3
static THREAD_LOCAL SF_EVENTQ* event_queue[NUM_EVENT_QUEUES];

static THREAD_LOCAL unsigned qIndex = 0;
static THREAD_LOCAL unsigned s_events = 0;
static THREAD_LOCAL unsigned qOverflow = 0;

//-------------------------------------------------
// the push/pop methods ensure that qIndex stays in
// bounds and that it is only popped after it was
// successfully pushed.
void SnortEventqPush(void)
{
    if ( qIndex < NUM_EVENT_QUEUES-1 )
        qIndex++;
    else
        qOverflow++;
}

void SnortEventqPop(void)
{
    if ( qOverflow > 0 )
        qOverflow--;
    else if ( qIndex > 0 )
        qIndex--;
}

//-------------------------------------------------
/*
**  Set default values
*/
EventQueueConfig* EventQueueConfigNew(void)
{
    EventQueueConfig* eqc =
        (EventQueueConfig*)SnortAlloc(sizeof(EventQueueConfig));

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

    free(eqc);
}

// Return 0 if no OTN since -1 return indicates queue limit reached. See
// fpFinalSelectEvent()
int SnortEventqAdd(const OptTreeNode* otn)
{
    RuleTreeNode* rtn = getRtnFromOtn(otn);

    if ( !rtn )
    {
        // If the rule isn't in the current policy,
        // don't add it to the event queue.
        return 0;
    }

    EventNode* en = (EventNode*)sfeventq_event_alloc(event_queue[qIndex]);

    if ( !en )
        return -1;

    en->otn = otn;
    en->rtn = rtn;

    if ( sfeventq_add(event_queue[qIndex], en) )
        return -1;

    s_events++;
    return 0;
}

// Preprocessors and decoder will call this function since
// they don't have access to the OTN.
int SnortEventqAdd(uint32_t gid, uint32_t sid, RuleType type)
{
    OptTreeNode* otn = GetOTN(gid, sid);

    if ( !otn )
        return 0;

    EventNode* en = (EventNode*)sfeventq_event_alloc(event_queue[qIndex]);

    if ( !en )
        return -1;

    en->otn = otn;
    en->rtn = nullptr;  // lookup later after ips policy selection
    en->type = type;

    if ( sfeventq_add(event_queue[qIndex], en) )
        return -1;

    s_events++;
    return 0;
}

bool event_is_enabled(uint32_t gid, uint32_t sid)
{
    OptTreeNode* otn = GetOTN(gid, sid);
    return ( otn != nullptr );
}

void SnortEventqNew(EventQueueConfig* eq_config)
{
    int i;

    for ( i = 0; i < NUM_EVENT_QUEUES; i++ )
    {
        event_queue[i] = sfeventq_new(eq_config->max_events,
            eq_config->log_events, sizeof(EventNode));

        if (event_queue[i] == NULL)
            FatalError("Failed to initialize Snort event queue.\n");
    }
}

void SnortEventqFree()
{
    int i;
    for ( i = 0; i < NUM_EVENT_QUEUES; i++ )
        sfeventq_free(event_queue[i]);
}

static int LogSnortEvents(void* event, void* user)
{
    if ( !event || !user )
        return 0;

    EventNode* en = (EventNode*)event;

    if ( !en->rtn )
    {
        en->rtn = getRtnFromOtn(en->otn);

        if ( !en->rtn )
            return 0;  // not enabled
    }

    if ( s_events > 0 )
        s_events--;

    SNORT_EVENTQ_USER* snort_user = (SNORT_EVENTQ_USER*)user;

    fpLogEvent(en->rtn, en->otn, (Packet*)snort_user->pkt);

    sfthreshold_reset();

    return 0;
}

/*
**  NAME
**    SnortEventqLog::
*/
/**
**  We return whether we logged events or not.  We've add a eventq user
**  structure so we can track whether the events logged were rule events
**  or preprocessor/decoder events.  The reason being that we don't want
**  to flush a TCP stream for preprocessor/decoder events, and cause
**  early flushing of the stream.
**
**  @return 1 logged events
**  @return 0 did not log events or logged only decoder/preprocessor events
*/
int SnortEventqLog(Packet* p)
{
    SNORT_EVENTQ_USER user;
    user.pkt = (void*)p;
    sfeventq_action(event_queue[qIndex], LogSnortEvents, (void*)&user);
    return 0;
}

static inline void reset_counts(void)
{
    pc.log_limit += s_events;
    s_events = 0;
}

void SnortEventqResetCounts(void)
{
    reset_counts();
}

void SnortEventqReset(void)
{
    sfeventq_reset(event_queue[qIndex]);
    reset_counts();
}

