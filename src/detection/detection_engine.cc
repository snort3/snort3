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

#include "events/sfeventq.h"
#include "filters/sfthreshold.h"
#include "framework/endianness.h"
#include "helpers/ring.h"
#include "latency/packet_latency.h"
#include "main/modules.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "main/thread.h"
#include "managers/inspector_manager.h"
#include "packet_io/active.h"
#include "parser/parser.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "utils/stats.h"

#include "context_switcher.h"
#include "detection_util.h"
#include "detect.h"
#include "fp_config.h"
#include "fp_detect.h"
#include "ips_context.h"

Trace TRACE_NAME(detection);

static THREAD_LOCAL unsigned s_events = 0;
static THREAD_LOCAL Ring<unsigned>* offload_ids = nullptr;

void DetectionEngine::thread_init()
{ offload_ids = new Ring<unsigned>(32); }  // FIXIT-H get size

void DetectionEngine::thread_term()
{ delete offload_ids; }

DetectionEngine::DetectionEngine()
{ context = Snort::get_switcher()->interrupt(); }

DetectionEngine::~DetectionEngine()
{
    clear_packet(context->packet);
    ContextSwitcher* sw = Snort::get_switcher();

    if ( context == sw->get_context() )
        sw->complete();
}

Packet* DetectionEngine::get_packet()
{ return context->packet; }

IpsContext* DetectionEngine::get_context()
{ return Snort::get_switcher()->get_context(); }

SF_EVENTQ* DetectionEngine::get_event_queue()
{ return Snort::get_switcher()->get_context()->equeue; }

Packet* DetectionEngine::get_current_packet()
{ return Snort::get_switcher()->get_context()->packet; }

void DetectionEngine::set_encode_packet(Packet* p)
{ Snort::get_switcher()->get_context()->encode_packet = p; }

Packet* DetectionEngine::get_encode_packet()
{ return Snort::get_switcher()->get_context()->encode_packet; }

MpseStash* DetectionEngine::get_stash()
{ return Snort::get_switcher()->get_context()->stash; }

// we need to stay in the current context until rebuild is successful
// any events while rebuilding will be logged against the current packet
Packet* DetectionEngine::set_packet()
{
    const IpsContext* c = Snort::get_switcher()->get_next();
    Packet* p = c->packet;

    p->pkth = c->pkth;
    p->data = c->buf;
    p->pkt = c->buf;

    p->reset();
    return p;
}

void DetectionEngine::clear_packet(Packet* p)
{
    log_events(p);
    reset(p);

    if ( p->endianness )
    {
        delete p->endianness;
        p->endianness = nullptr;
    }
}

uint8_t* DetectionEngine::get_buffer(unsigned& max)
{
    max = IpsContext::buf_size;
    return Snort::get_switcher()->get_context()->buf;
}

// similar to set_packet() because http_inspect does everything via the
// splitter, ie before reassembly.  maybe that should change.  for now
// we do it this way.
void DetectionEngine::set_next_file_data(const DataPointer& dp)
{
    IpsContext* c = Snort::get_switcher()->get_next();
    c->file_data = dp;
}

void DetectionEngine::get_next_file_data(DataPointer& dp)
{
    const IpsContext* c = Snort::get_switcher()->get_next();
    dp = c->file_data;
}

void DetectionEngine::set_file_data(const DataPointer& dp)
{ Snort::get_switcher()->get_context()->file_data = dp; }

void DetectionEngine::get_file_data(DataPointer& dp)
{ dp = Snort::get_switcher()->get_context()->file_data; }

void DetectionEngine::set_data(unsigned id, IpsContextData* p)
{ Snort::get_switcher()->get_context()->set_context_data(id, p); }

IpsContextData* DetectionEngine::get_data(unsigned id)
{ return Snort::get_switcher()->get_context()->get_context_data(id); }

void DetectionEngine::disable_all(Packet* p)
{ p->context->active_rules = IpsContext::NONE; }

bool DetectionEngine::all_disabled(Packet* p)
{ return p->context->active_rules == IpsContext::NONE; }

void DetectionEngine::disable_content(Packet* p)
{
    if ( p->context->active_rules == IpsContext::CONTENT )
        p->context->active_rules = IpsContext::NON_CONTENT;
}

void DetectionEngine::enable_content(Packet* p)
{ p->context->active_rules = IpsContext::CONTENT; }

bool DetectionEngine::content_enabled(Packet* p)
{ return p->context->active_rules == IpsContext::CONTENT; }

IpsContext::ActiveRules DetectionEngine::get_detects(Packet* p)
{ return p->context->active_rules; }

void DetectionEngine::set_detects(Packet* p, IpsContext::ActiveRules ar)
{ p->context->active_rules = ar; }

bool DetectionEngine::offloaded(Packet* p)
{ return p->flow and p->flow->is_offloaded(); }

void DetectionEngine::idle()
{
    if ( !offload_ids )
        return;

    while ( !offload_ids->empty() )
    {
        const struct timespec blip = { 0, 1 };
        trace_logf(detection, "%lu de::sleep\n", pc.total_from_daq);
        nanosleep(&blip, nullptr);
        onload();
    }
    trace_logf(detection, "%lu de::idle (r=%d)\n", pc.total_from_daq, offload_ids->count());
}

void DetectionEngine::onload(Flow* flow)
{
    while ( flow->is_offloaded() )
    {
        const struct timespec blip = { 0, 1 };
        trace_logf(detection, "%lu de::sleep\n", pc.total_from_daq);
        nanosleep(&blip, nullptr);
        onload();
    }
}

void DetectionEngine::onload()
{
    ContextSwitcher* sw = Snort::get_switcher();
    unsigned* id = offload_ids->read();
    IpsContext* c = sw->get_context(*id);

    assert(c->offload);

    if ( !c->onload )
        return;

    trace_logf(detection, "%lu de::onload %u (r=%d)\n",
        pc.total_from_daq, *id, offload_ids->count());

    Packet* p = c->packet;
    p->flow->clear_offloaded();

    c->offload->join();
    delete c->offload;
    c->offload = nullptr;

    offload_ids->pop();
    sw->resume(*id);

    fp_onload(p);
    InspectorManager::clear(p);
    log_events(p);
    reset(p);
    clear_packet(p);

    sw->complete();
}

bool DetectionEngine::offload(Packet* p)
{
    ContextSwitcher* sw = Snort::get_switcher();

    if ( p->type() != PktType::PDU or (p->dsize < snort_conf->offload_limit) or !sw->can_hold() )
    {
        fp_local(p);
        return false;
    }
    assert(p == p->context->packet);
    onload(p->flow);  // FIXIT-H ensures correct sequencing, suboptimal

    p->flow->set_offloaded();
    pc.offloads++;

    assert(p->context == sw->get_context());

    unsigned id = sw->suspend();
    offload_ids->put(id);

    trace_logf(detection, "%lu de::offload %u (r=%d)\n",
        pc.total_from_daq, id, offload_ids->count());

    p->context->onload = false;
    p->context->offload = new std::thread(fp_offload, p, snort_conf);

    return true;
}

bool DetectionEngine::detect(Packet* p)
{
    assert(p);
    Profile profile(detectPerfStats);
    
    if ( !p->ptrs.ip_api.is_valid() )
        return false;
    
    if ( p->packet_flags & PKT_PASS_RULE )
        return false;
        
    if ( PacketLatency::fastpath() )
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
        return offload(p);

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
            enable_content(p);
            p->alt_dsize = 0;  // FIXIT-H should be redundant

            InspectorManager::execute(p);
            inspected = true;

            Active::apply_delayed_action(p);

            if ( !all_disabled(p) )
            {
                if ( detect(p) )
                    return;
            }
        }
        enable_tags();

        // By checking tagging here, we make sure that we log the
        // tagged packet whether it generates an alert or not.

        if ( p->has_ip() )
            check_tags(p);

        if ( offloaded(p) )
            return;

        // clear closed sessions here after inspection since non-stream
        // inspectors may depend on flow information
        // FIXIT-H but this result in double clearing?  should normal
        // clear_session() calls be deleted from stream?  this is a
        // performance hit on short-lived flows

        Stream::check_flow_closed(p);

        if ( inspected )
            InspectorManager::clear(p);
    }

    Profile profile(eventqPerfStats);

    log_events(p);
    reset(p);

    Stream::check_flow_block_pending(p);
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

int DetectionEngine::queue_event(unsigned gid, unsigned sid, RuleType type)
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
    SF_EVENTQ* pq = p->context->equeue;
    sfeventq_action(pq, ::log_events, (void*)p);
    return 0;
}

void DetectionEngine::reset_counts()
{
    pc.log_limit += s_events;
    s_events = 0;
}

void DetectionEngine::reset(Packet* p)
{
    SF_EVENTQ* pq = p->context->equeue;
    sfeventq_reset(pq);
    reset_counts();
}

