//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection_engine.h"

#include "actions/act_replace.h"
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
#include "detect_trace.h"
#include "fp_config.h"
#include "fp_detect.h"
#include "ips_context.h"
#include "regex_offload.h"

static THREAD_LOCAL RegexOffload* offloader = nullptr;
static THREAD_LOCAL uint64_t context_num = 0;

using namespace snort;

//--------------------------------------------------------------------------
// basic de
//--------------------------------------------------------------------------

void DetectionEngine::thread_init()
{ offloader = new RegexOffload(SnortConfig::get_conf()->offload_threads); }

void DetectionEngine::thread_term()
{ delete offloader; }

DetectionEngine::DetectionEngine()
{
    context = Snort::get_switcher()->interrupt();
    context->file_data = { nullptr, 0 };
    reset();
}

DetectionEngine::~DetectionEngine()
{
    ContextSwitcher* sw = Snort::get_switcher();

    if ( context == sw->get_context() )
    {
        finish_packet(context->packet);
        sw->complete();
    }
}

void DetectionEngine::reset()
{
    IpsContext* c = Snort::get_switcher()->get_context();
    c->context_num = ++context_num;
    c->alt_data.len = 0;  // FIXIT-H need context::reset()
}

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

// we need to stay in the current context until rebuild is successful
// any events while rebuilding will be logged against the current packet
// however, rebuild is always in the next context, not current.
Packet* DetectionEngine::set_next_packet(Packet* parent)
{
    IpsContext* c = Snort::get_switcher()->get_next();
    if ( parent )
    {
        c->snapshot_flow(parent->flow);
        c->packet_number = parent->context->packet_number;
    }
    else
        c->packet_number = get_packet_number();

    Packet* p = c->packet;

    p->pkth = c->pkth;
    p->data = c->buf;
    p->pkt = c->buf;

    p->reset();
    return p;
}

void DetectionEngine::finish_packet(Packet* p)
{
    log_events(p);
    clear_events(p);
    p->release_helpers();

    // clean up any failed rebuilds
    const IpsContext* c = Snort::get_switcher()->get_next();
    c->packet->release_helpers();
}

uint8_t* DetectionEngine::get_buffer(unsigned& max)
{
    max = IpsContext::buf_size;
    return Snort::get_switcher()->get_context()->buf;
}

uint8_t* DetectionEngine::get_next_buffer(unsigned& max)
{
    max = IpsContext::buf_size;
    return Snort::get_switcher()->get_next()->buf;
}

DataBuffer& DetectionEngine::get_alt_buffer(Packet* p)
{
    assert(p);
    return p->context->alt_data;
}

void DetectionEngine::set_file_data(const DataPointer& dp)
{ Snort::get_switcher()->get_context()->file_data = dp; }

void DetectionEngine::get_file_data(DataPointer& dp)
{ dp = Snort::get_switcher()->get_context()->file_data; }

void DetectionEngine::set_data(unsigned id, IpsContextData* p)
{ Snort::get_switcher()->get_context()->set_context_data(id, p); }

IpsContextData* DetectionEngine::get_data(unsigned id)
{ return Snort::get_switcher()->get_context()->get_context_data(id); }

IpsContextData* DetectionEngine::get_data(unsigned id, IpsContext* context)
{
    if ( context )
        return context->get_context_data(id);

    return DetectionEngine::get_data(id);
}

void DetectionEngine::add_replacement(const std::string& s, unsigned off)
{ 
    Replacement r;

    r.data = s;
    r.offset = off;
    Snort::get_switcher()->get_context()->rpl.push_back(r); 
}

bool DetectionEngine::get_replacement(std::string& s, unsigned& off)
{ 
    if ( Snort::get_switcher()->get_context()->rpl.empty() )
        return false;

    auto rep = Snort::get_switcher()->get_context()->rpl.back();

    s = rep.data;
    off = rep.offset;

    Snort::get_switcher()->get_context()->rpl.pop_back();
    return true;
}

void DetectionEngine::clear_replacement()
{
    Snort::get_switcher()->get_context()->rpl.clear();
}

void DetectionEngine::disable_all(Packet* p)
{ p->context->active_rules = IpsContext::NONE; }

bool DetectionEngine::all_disabled(Packet* p)
{ return p->context->active_rules == IpsContext::NONE; }

void DetectionEngine::disable_content(Packet* p)
{
    if ( p->context->active_rules == IpsContext::CONTENT )
        p->context->active_rules = IpsContext::NON_CONTENT;

    trace_logf(detection, TRACE_PKT_DETECTION,
        "Disabled content detect, packet %" PRIu64"\n", p->context->packet_number);
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

void DetectionEngine::set_check_tags(bool enable)
{ Snort::get_switcher()->get_context()->check_tags = enable; }

bool DetectionEngine::get_check_tags()
{ return Snort::get_switcher()->get_context()->check_tags; }

//--------------------------------------------------------------------------
// offload / onload
//--------------------------------------------------------------------------

void DetectionEngine::idle()
{
    if (offloader)
    {
        while ( offloader->count() )
        {
            trace_logf(detection,
                TRACE_DETECTION_ENGINE,  "(wire) %" PRIu64 " de::sleep\n", get_packet_number());

            const struct timespec blip = { 0, 1 };
            nanosleep(&blip, nullptr);
            onload();
        }
        trace_logf(detection,  TRACE_DETECTION_ENGINE, "(wire) %" PRIu64 " de::idle (r=%d)\n",
            get_packet_number(), offloader->count());

        offloader->stop();
    }
}

void DetectionEngine::onload(Flow* flow)
{
    while ( flow->is_offloaded() )
    {
        const struct timespec blip = { 0, 1 };
        trace_logf(detection,
            TRACE_DETECTION_ENGINE, "(wire) %" PRIu64 " de::sleep\n", get_packet_number());

        nanosleep(&blip, nullptr);
        onload();
    }
    assert(!Snort::get_switcher()->on_hold(flow));
    assert(!offloader->on_hold(flow));
}

void DetectionEngine::onload()
{
    unsigned id;

    if ( !offloader->get(id) )
        return;

    ContextSwitcher* sw = Snort::get_switcher();
    IpsContext* c = sw->get_context(id);
    assert(c);

    trace_logf(detection, TRACE_DETECTION_ENGINE, "%" PRIu64 " de::onload %u (r=%d)\n",
        c->packet_number, id, offloader->count());

    Packet* p = c->packet;
    p->flow->clear_offloaded();

    sw->resume(id);

    fp_onload(p);
    finish_packet(p);

    InspectorManager::clear(p);
    sw->complete();
}

bool DetectionEngine::offload(Packet* p)
{
    ContextSwitcher* sw = Snort::get_switcher();

    if ( p->type() != PktType::PDU or
         p->dsize < SnortConfig::get_conf()->offload_limit or
         !sw->can_hold() or
         !offloader->available() )
    {
        fp_local(p);
        return false;
    }
    assert(p == p->context->packet);
    onload(p->flow);  // FIXIT-L just assert !offloaded?

    assert(p->context == sw->get_context());
    unsigned id = sw->suspend();

    trace_logf(detection, TRACE_DETECTION_ENGINE, "%" PRIu64 " de::offload %u (r=%d)\n",
        p->context->packet_number, id, offloader->count());

    p->flow->set_offloaded();
    p->context->conf = SnortConfig::get_conf();

    offloader->put(id, p);
    pc.offloads++;

    return true;
}

//--------------------------------------------------------------------------
// detection / inspection
//--------------------------------------------------------------------------

bool DetectionEngine::detect(Packet* p, bool offload_ok)
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
    // Currently, if a rule is found on any IP layer, we perform the detect routine
    // on the entire packet. Instead, we should only perform detect on that layer!!
    switch ( p->type() )
    {
    case PktType::PDU:
        if ( offload_ok )
            return offload(p);
        // fall thru

    case PktType::IP:
    case PktType::TCP:
    case PktType::UDP:
    case PktType::ICMP:
    case PktType::FILE:
        fp_local(p);
        break;

    default:
        break;
    }
    return false;
}

void DetectionEngine::inspect(Packet* p)
{
    bool inspected = false;
    {
        PacketLatency::Context pkt_latency_ctx { p };

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

            if ( !all_disabled(p) )
            {
                if ( detect(p, true) )
                    return; // don't finish out offloaded packets
            }
        }
        DetectionEngine::set_check_tags();

        // By checking tagging here, we make sure that we log the
        // tagged packet whether it generates an alert or not.

        if ( p->has_ip() )
            check_tags(p);

        InspectorManager::probe(p);
    }

    log_events(p);
    Active::apply_delayed_action(p);

    // clear closed sessions here after inspection since non-stream
    // inspectors may depend on flow information
    // this also handles block pending state
    Stream::check_flow_closed(p);

    if ( inspected )
        InspectorManager::clear(p);

    clear_events(p);
}

//--------------------------------------------------------------------------
// events
//--------------------------------------------------------------------------

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

    return 0;
}

int DetectionEngine::queue_event(unsigned gid, unsigned sid, Actions::Type type)
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
    Profile profile(eventqPerfStats);
    SF_EVENTQ* pq = p->context->equeue;
    sfeventq_action(pq, ::log_events, (void*)p);
    return 0;
}

void DetectionEngine::clear_events(Packet* p)
{
    SF_EVENTQ* pq = p->context->equeue;
    pc.log_limit += sfeventq_reset(pq);
}

