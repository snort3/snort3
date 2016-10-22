//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// detection_engine.h author Russ Combs <rucombs@cisco.com>

#include "detection_engine.h"

#include "detection/detection_engine.h"
#include "events/sfeventq.h"
#include "filters/sfthreshold.h"
#include "latency/packet_latency.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "managers/inspector_manager.h"
#include "packet_io/active.h"
#include "parser/parser.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "utils/stats.h"

#include "context_switcher.h"
#include "detect.h"
#include "fp_detect.h"
#include "ips_context.h"

static THREAD_LOCAL unsigned s_events = 0;

THREAD_LOCAL DetectionEngine::ActiveRules active_rules = DetectionEngine::NONE;

DetectionEngine::DetectionEngine()
{ Snort::get_switcher()->interrupt(); }

DetectionEngine::~DetectionEngine()
{ clear_packet(); }

SF_EVENTQ* DetectionEngine::get_event_queue()
{ return Snort::get_switcher()->get_context()->equeue; }

Packet* DetectionEngine::get_current_packet()
{ return Snort::get_switcher()->get_context()->packet; }

Packet* DetectionEngine::get_packet()
{ return get_current_packet(); }

Packet* DetectionEngine::set_packet()
{
    // we need to stay in the current context until rebuild is successful
    // any events while rebuilding will be logged against the current packet
    // FIXIT-H bypass the interrupt / complete
 
    ContextSwitcher* sw = Snort::get_switcher();
    const IpsContext* c = sw->interrupt();
    Packet* p = c->packet;
    sw->complete();

    p->pkth = c->pkth;
    p->data = c->buf;
    p->reset();

    return p;
}

void DetectionEngine::clear_packet()
{
    ContextSwitcher* sw = Snort::get_switcher();
    Packet* p = sw->get_context()->packet;

    log_events(p);
    reset();

    if ( p->endianness )
    {
        delete p->endianness;
        p->endianness = nullptr;
    }

    sw->complete();
}

uint8_t* DetectionEngine::get_buffer(unsigned& max)
{
    max = IpsContext::buf_size;
    return Snort::get_switcher()->get_context()->buf;
}

void DetectionEngine::set_data(unsigned id, IpsContextData* p)
{ Snort::get_switcher()->get_context()->set_context_data(id, p); }

IpsContextData* DetectionEngine::get_data(unsigned id)
{ return Snort::get_switcher()->get_context()->get_context_data(id); }

DetectionEngine::ActiveRules DetectionEngine::get_detects()
{ return active_rules; }

void DetectionEngine::set_detects(ActiveRules ar)
{ active_rules = ar; }

void DetectionEngine::disable_content()
{
    if ( active_rules == CONTENT )
        active_rules = NON_CONTENT;
}

void DetectionEngine::disable_all()
{ active_rules = NONE; }

bool DetectionEngine::detect(Packet* p)
{
    assert(p);
    Profile profile(detectPerfStats);
    
    if ( !p->ptrs.ip_api.is_valid() )
        return false;
    
    if ( p->packet_flags & PKT_PASS_RULE )
        return false;
        
    // FIXIT-M restrict detect to current ip layer
    // Curently, if a rule is found on any IP layer, we perform the detect routine
    // on the entire packet. Instead, we should only perform detect on that layer!!
    switch ( p->type() )
    {
    case PktType::IP:
    case PktType::TCP:
    case PktType::UDP:
    case PktType::ICMP:
    case PktType::PDU:
    case PktType::FILE:
        if ( PacketLatency::fastpath() )
            return false;

        return fpEvalPacket(p);

    default:
        break;
    }
    return false;
}

void DetectionEngine::inspect(Packet* p)
{
    {
        PacketLatency::Context pkt_latency_ctx { p };
        bool inspected = false;

        if ( p->ptrs.decode_flags & DECODE_ERR_FLAGS )
        {
            if ( SnortConfig::inline_mode() and
                SnortConfig::checksum_drop(p->ptrs.decode_flags & DECODE_ERR_CKSUM_ALL) )
            {
                Active::drop_packet(p);
            }
        }
        else
        {
            active_rules = CONTENT;
            p->alt_dsize = 0;  // FIXIT-H should be redundant

            InspectorManager::execute(p);
            inspected = true;

            Active::apply_delayed_action(p);

            if ( active_rules > NONE )
                detect(p);
        }
        enable_tags();

        // clear closed sessions here after inspection since non-stream
        // inspectors may depend on flow information
        // FIXIT-H but this result in double clearing?  should normal
        // clear_session() calls be deleted from stream?  this is a
        // performance hit on short-lived flows
        Stream::check_flow_closed(p);

        /*
        ** By checking tagging here, we make sure that we log the
        ** tagged packet whether it generates an alert or not.
        */
        if ( p->has_ip() )
            check_tags(p);

        if ( inspected )
            InspectorManager::clear(p);
    }

    Profile profile(eventqPerfStats);
    log_events(p);
    reset();
}

// Return 0 if no OTN since -1 return indicates queue limit reached.
// See fpFinalSelectEvent()
int DetectionEngine::queue_event(const OptTreeNode* otn)
{
    RuleTreeNode* rtn = getRtnFromOtn(otn);

    if ( !rtn )
    {
        // If the rule isn't in the current policy,
        // don't add it to the event queue.
        return 0;
    }

    SF_EVENTQ* pq = get_event_queue();
    EventNode* en = (EventNode*)sfeventq_event_alloc(pq);

    if ( !en )
        return -1;

    en->otn = otn;
    en->rtn = rtn;

    if ( sfeventq_add(pq, en) )
        return -1;

    s_events++;
    return 0;
}

int DetectionEngine::queue_event(uint32_t gid, uint32_t sid, RuleType type)
{
    OptTreeNode* otn = GetOTN(gid, sid);

    if ( !otn )
        return 0;

    SF_EVENTQ* pq = get_event_queue();
    EventNode* en = (EventNode*)sfeventq_event_alloc(pq);

    if ( !en )
        return -1;

    en->otn = otn;
    en->rtn = nullptr;  // lookup later after ips policy selection
    en->type = type;

    if ( sfeventq_add(pq, en) )
        return -1;

    s_events++;
    return 0;
}

static int log_events(void* event, void* user)
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

    fpLogEvent(en->rtn, en->otn, (Packet*)user);
    sfthreshold_reset();

    return 0;
}

/*
**  We return whether we logged events or not.  We've add a eventq user
**  structure so we can track whether the events logged were rule events
**  or preprocessor/decoder events.  The reason being that we don't want
**  to flush a TCP stream for preprocessor/decoder events, and cause
**  early flushing of the stream.
*/
int DetectionEngine::log_events(Packet* p)
{
    SF_EVENTQ* pq = get_event_queue();
    sfeventq_action(pq, ::log_events, (void*)p);
    return 0;
}

void DetectionEngine::reset_counts()
{
    pc.log_limit += s_events;
    s_events = 0;
}

void DetectionEngine::reset()
{
    SF_EVENTQ* pq = get_event_queue();
    sfeventq_reset(pq);
    reset_counts();
}

