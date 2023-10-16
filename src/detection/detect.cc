//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

/*   Dan Roelker <droelker@sourcefire.com>
**   Marc Norton <mnorton@sourcefire.com>
**
**   5.7.02: Added interface for new detection engine. (Norton/Roelker)
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detect.h"

#include "events/event.h"
#include "latency/packet_latency.h"
#include "main/snort_config.h"
#include "managers/event_manager.h"
#include "managers/inspector_manager.h"
#include "packet_io/active.h"
#include "ports/port_object.h"
#include "profiler/profiler_defs.h"
#include "reputation/reputation_common.h"
#include "sfip/sf_ipvar.h"
#include "stream/stream.h"
#include "utils/stats.h"

#include "detection_engine.h"
#include "fp_detect.h"
#include "rules.h"
#include "tag.h"
#include "treenodes.h"

using namespace snort;

THREAD_LOCAL ProfileStats eventqPerfStats;

bool snort_ignore(Packet*) { return true; }

bool snort_log(Packet* p)
{
    pc.log_pkts++;
    EventManager::call_loggers(nullptr, p, nullptr, nullptr);

    return true;
}

void CallLogFuncs(Packet* p, ListHead* head, Event* event, const char* msg)
{
    event->update_event_id(p->context->conf->get_event_log_id());

    DetectionEngine::set_check_tags(false);
    pc.log_pkts++;

    OutputSet* idx = head ? head->LogList : nullptr;
    EventManager::call_loggers(idx, p, msg, event);
}

void CallLogFuncs(Packet* p, const OptTreeNode* otn, ListHead* head)
{
    Event event;

    // FIXIT-L this and the same below should be refactored to not need const_cast
    event.sig_info = const_cast<SigInfo*>(&otn->sigInfo);
    event.ref_time.tv_sec = p->pkth->ts.tv_sec;
    event.ref_time.tv_usec = p->pkth->ts.tv_usec;
    event.update_event_id_and_ref(p->context->conf->get_event_log_id());
    if (head and head->ruleListNode)
        event.action_string = head->ruleListNode->name;

    DetectionEngine::set_check_tags(false);
    pc.log_pkts++;

    const uint8_t* data = nullptr;
    uint16_t dsize = 0;

    if (p->flow && p->flow->gadget)
        data = p->flow->gadget->adjust_log_packet(p, dsize);

    uint16_t old_dsize = 0;
    const uint8_t* old_data = nullptr;
    if (data)
    {
        old_dsize = p->dsize;
        old_data = p->data;
        p->data = data;
        p->dsize = dsize;
    }

    OutputSet* idx = head ? head->LogList : nullptr;
    EventManager::call_loggers(idx, p, otn->sigInfo.message.c_str(), &event);

    if (data)
    {
        p->data = old_data;
        p->dsize = old_dsize;
        delete[] data;
    }
}

void CallAlertFuncs(Packet* p, const OptTreeNode* otn, ListHead* head)
{
    Event event;

    event.sig_info = const_cast<SigInfo*>(&otn->sigInfo);
    event.ref_time.tv_sec = p->pkth->ts.tv_sec;
    event.ref_time.tv_usec = p->pkth->ts.tv_usec;
    event.update_event_id_and_ref(p->context->conf->get_event_log_id());
    if (head and head->ruleListNode)
        event.action_string = head->ruleListNode->name;

    pc.total_alert_pkts++;

    if ( otn->sigInfo.gid != GID_REPUTATION )
    {
        /* Don't include IP Reputation events in count */
        pc.alert_pkts++;
    }

    OutputSet* idx = head ? head->AlertList : nullptr;
    EventManager::call_alerters(idx, p, otn->sigInfo.message.c_str(), event);
}

/*
**  This is where we check to see if we tag the packet.  We only do
**  this if we've alerted on a non-pass rule and the packet is not
**  rebuilt.
**
**  We don't log rebuilt packets because the output plugins log the
**  individual packets of a rebuilt stream, so we don't want to dup
**  tagged packets for rebuilt streams.
*/
void check_tags(Packet* p)
{
    SigInfo info;
    Event event(info);

    if ( DetectionEngine::get_check_tags() and !(p->packet_flags & PKT_REBUILT_STREAM) )
    {
        void* listhead = nullptr;

        if (CheckTagList(p, event, &listhead))
        {
            /* if we find a match, we want to send the packet to the
             * logging mechanism
             */
            CallLogFuncs(p, (ListHead*)listhead, &event, "Tagged Packet");
        }
    }
}

