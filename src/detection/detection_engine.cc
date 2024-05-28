//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "events/event_queue.h"
#include "events/sfeventq.h"
#include "filters/sfthreshold.h"
#include "framework/endianness.h"
#include "framework/ips_action.h"
#include "helpers/ring.h"
#include "latency/packet_latency.h"
#include "main/analyzer.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "managers/mpse_manager.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "parser/parser.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "time/packet_time.h"
#include "trace/trace_api.h"
#include "utils/stats.h"

#include "context_switcher.h"
#include "detection_buf.h"
#include "detection_module.h"
#include "detect.h"
#include "detect_trace.h"
#include "fp_config.h"
#include "fp_detect.h"
#include "ips_context.h"
#include "ips_context_data.h"
#include "regex_offload.h"

using namespace snort;

static THREAD_LOCAL RegexOffload* offloader = nullptr;
bool DetectionEngine::offload_enabled = false;

//--------------------------------------------------------------------------
// basic de
//--------------------------------------------------------------------------

void DetectionEngine::thread_init()
{
    const SnortConfig* sc = SnortConfig::get_conf();
    FastPatternConfig* fp = sc->fast_pattern_config;
    const MpseApi* offload_search_api = fp->get_offload_search_api();

    // Note: offload_threads is really the maximum number of offload_requests
    if (offload_search_api and MpseManager::is_async_capable(offload_search_api))
    {
        // Check that poll functionality has been provided
        assert(MpseManager::is_poll_capable(offload_search_api));

        // If the search method is async capable then the searches will be performed directly
        // by the search engine, without requiring a processing thread.
        offloader = RegexOffload::get_offloader(sc->offload_threads, false);
    }
    else
    {
        const MpseApi* search_api = fp->get_search_api();

        if (MpseManager::is_async_capable(search_api))
        {
            assert(MpseManager::is_poll_capable(search_api));
            offloader = RegexOffload::get_offloader(sc->offload_threads, false);
        }
        else
        {
            // If the search method is not async capable then offloaded searches will be performed
            // in a separate processing thread that the RegexOffload instance needs to create.
            offloader = RegexOffload::get_offloader(sc->offload_threads, true);
        }
    }
}

void DetectionEngine::thread_term()
{
    delete offloader;
}

// Not sure why cppcheck doesn't think context is initialized
// cppcheck-suppress uninitMemberVar
DetectionEngine::DetectionEngine()
{
    context = Analyzer::get_switcher()->interrupt();

    context->file_data = DataPointer(nullptr, 0);
    context->file_data_id = 0;

    reset();
}

DetectionEngine::~DetectionEngine()
{
    if ( context == Analyzer::get_switcher()->get_context() )
    {
        // finish_packet is called here so that we clear wire packets at the right time
        // FIXIT-L if might not be needed anymore with wire packet checks in finish_packet
        finish_packet(context->packet, true);
    }
}

void DetectionEngine::enable_offload()
{ offload_enabled = true; }

void DetectionEngine::reset()
{
    IpsContext* c = Analyzer::get_switcher()->get_context();
    c->alt_data.len = 0;  // FIXIT-L need context::reset()
}

IpsContext* DetectionEngine::get_context()
{ return Analyzer::get_switcher()->get_context(); }

SF_EVENTQ* DetectionEngine::get_event_queue()
{ return Analyzer::get_switcher()->get_context()->equeue; }

Packet* DetectionEngine::get_current_packet()
{
    const IpsContext* c = Analyzer::get_switcher()->get_context();
    assert(c);
    return c->packet;
}

Packet* DetectionEngine::get_current_wire_packet()
{
    const IpsContext* c = Analyzer::get_switcher()->get_context();
    assert(c);
    return c->wire_packet;
}

void DetectionEngine::set_encode_packet(Packet* p)
{ Analyzer::get_switcher()->get_context()->encode_packet = p; }

Packet* DetectionEngine::get_encode_packet()
{ return Analyzer::get_switcher()->get_context()->encode_packet; }

// we need to stay in the current context until rebuild is successful
// any events while rebuilding will be logged against the current packet
// however, rebuild is always in the next context, not current.
Packet* DetectionEngine::set_next_packet(const Packet* parent, Flow* flow)
{
    static THREAD_LOCAL Active shutdown_active;
    static THREAD_LOCAL ActiveAction* shutdown_action = nullptr;

    wait_for_context();
    IpsContext* c = Analyzer::get_switcher()->get_next();

    Packet* p = c->packet;

    if ( parent )
    {
        if ( parent->flow )
            c->snapshot_flow(parent->flow);
        c->packet_number = parent->context->packet_number;
        c->wire_packet = parent->context->wire_packet;
    }
    else
    {
        if ( flow )
            p->context->snapshot_flow(flow);
        c->packet_number = pc.analyzed_pkts;
        c->wire_packet = nullptr;
    }

    packet_gettimeofday(&c->pkth->ts);
    p->pkth = c->pkth;
    p->data = c->buf;
    p->pkt = c->buf;

    // normal rebuild
    if ( parent )
    {
        p->daq_msg = parent->daq_msg;
        p->daq_instance = parent->daq_instance;
        p->active = parent->active;
        p->action = parent->action;
    }

    // processing but parent is already gone (flow cache flush etc..) or
    // shutdown, so use a dummy so null checking is not needed everywhere
    else
    {
        p->daq_msg = nullptr;
        p->daq_instance = nullptr;
        p->action = &shutdown_action;
        p->active = &shutdown_active;
        shutdown_active.reset();
    }

    p->reset();

    p->packet_flags |= PKT_WAS_SET;

    if ( parent )
        p->packet_flags |= PKT_HAS_PARENT;

    return p;
}

void DetectionEngine::finish_inspect_with_latency(Packet* p)
{
    DetectionEngine::set_check_tags(p);

    // By checking tagging here, we make sure that we log the
    // tagged packet whether it generates an alert or not.

    if ( p->has_ip() )
        check_tags(p);

    InspectorManager::probe(p);
}

void DetectionEngine::finish_inspect(Packet* p, bool inspected)
{
    log_events(p);

    if ( PacketTracer::is_daq_activated() )
        populate_trace_data();

    if ( p->active )
    {
        if ( p->active->session_was_blocked() and ( p->active->keep_pruned_flow() or
            ( p->active->keep_timedout_flow() and ( p->is_tcp() or p->pseudo_type == PSEUDO_PKT_TCP ) ) ) )
        {
            p->flow->ssn_state.session_flags |= SSNFLAG_KEEP_FLOW;
        }

        p->active->apply_delayed_action(p);
    }

    p->context->post_detection();

    if ( inspected and !p->context->next() )
        InspectorManager::clear(p);

    // clear closed sessions here after inspection since non-stream
    // inspectors may depend on flow information
    // this also handles block pending state
    // must only be done for terminal packets to avoid yoinking stream_tcp state
    // while processing a PDU
    if ( !p->has_parent() )
        Stream::check_flow_closed(p);

    clear_events(p);
}

void DetectionEngine::finish_packet(Packet* p, bool flow_deletion)
{
    ContextSwitcher* sw = Analyzer::get_switcher();

    log_events(p);
    clear_events(p);
    p->release_helpers();

    // clean up any failed rebuilds
    if ( sw->idle_count() )
    {
        const IpsContext* c = sw->get_next();
        c->packet->release_helpers();
    }

    if ( flow_deletion or p->is_rebuilt() )
        sw->complete();
}

uint8_t* DetectionEngine::get_next_buffer(unsigned& max)
{
    max = IpsContext::buf_size;
    return Analyzer::get_switcher()->get_next()->buf;
}

void DetectionEngine::set_file_data(const DataPointer& dp)
{
    auto c = Analyzer::get_switcher()->get_context();
    c->file_data = dp;
    c->file_data_id = 0;
    c->file_data_drop_sse = false;
    c->file_data_no_sse = false;
}

void DetectionEngine::set_file_data(const DataPointer& dp, uint64_t id, bool is_accum, bool no_flow)
{
    auto c = Analyzer::get_switcher()->get_context();
    c->file_data = dp;
    c->file_data_id = id;
    c->file_data_drop_sse = is_accum;
    c->file_data_no_sse = no_flow;
}

const DataPointer& DetectionEngine::get_file_data(const IpsContext* c)
{ return c->file_data; }

const DataPointer& DetectionEngine::get_file_data(const IpsContext* c, uint64_t& id, bool& drop_sse, bool& no_sse)
{
    id = c->file_data_id;
    drop_sse = c->file_data_drop_sse;
    no_sse = c->file_data_no_sse;
    return c->file_data;
}

void DetectionEngine::set_data(unsigned id, IpsContextData* p)
{ Analyzer::get_switcher()->get_context()->set_context_data(id, p); }

IpsContextData* DetectionEngine::get_data(unsigned id)
{ return Analyzer::get_switcher()->get_context()->get_context_data(id); }

IpsContextData* DetectionEngine::get_data(unsigned id, IpsContext* context)
{
    if ( context )
        return context->get_context_data(id);

    ContextSwitcher* sw = Analyzer::get_switcher();

    if ( !sw )
        return nullptr;

    return sw->get_context()->get_context_data(id);
}

void DetectionEngine::add_replacement(const std::string& s, unsigned off)
{
    Replacement r;

    r.data = s;
    r.offset = off;
    Analyzer::get_switcher()->get_context()->rpl.emplace_back(r);
}

bool DetectionEngine::get_replacement(std::string& s, unsigned& off)
{
    if ( Analyzer::get_switcher()->get_context()->rpl.empty() )
        return false;

    auto rep = Analyzer::get_switcher()->get_context()->rpl.back();

    s = rep.data;
    off = rep.offset;

    Analyzer::get_switcher()->get_context()->rpl.pop_back();
    return true;
}

void DetectionEngine::clear_replacement()
{
    Analyzer::get_switcher()->get_context()->rpl.clear();
}

void DetectionEngine::disable_all(Packet* p)
{
    p->context->active_rules = IpsContext::NONE;
    debug_logf(detection_trace, TRACE_PKT_DETECTION, p,
        "Disabled all detect, packet %" PRIu64"\n", p->context->packet_number);
}

bool DetectionEngine::all_disabled(Packet* p)
{ return p->context->active_rules == IpsContext::NONE; }

void DetectionEngine::disable_content(Packet* p)
{
    if ( p->context->active_rules == IpsContext::CONTENT )
        p->context->active_rules = IpsContext::NON_CONTENT;

    debug_logf(detection_trace, TRACE_PKT_DETECTION, p,
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

void DetectionEngine::set_check_tags(Packet* p, bool enable)
{ p->context->check_tags = enable; }

bool DetectionEngine::get_check_tags(Packet* p)
{ return p->context->check_tags; }

//--------------------------------------------------------------------------
// offload / onload
//--------------------------------------------------------------------------

bool DetectionEngine::do_offload(Packet* p)
{
    ContextSwitcher* sw = Analyzer::get_switcher();

    assert(p == p->context->packet);
    assert(p->context == sw->get_context());

    debug_logf(detection_trace, TRACE_DETECTION_ENGINE, p,
        "%" PRIu64 " de::offload %" PRIu64 " (r=%d)\n",
        p->context->packet_number, p->context->context_num, offloader->count());

    sw->suspend();
    p->set_offloaded();

    offloader->put(p);
    pc.offloads++;

#ifdef REG_TEST
    onload();
    return false;
#else
    return true;
#endif
}

bool DetectionEngine::offload(Packet* p)
{
    ContextSwitcher* sw = Analyzer::get_switcher();
    fp_partial(p);

    if ( p->dsize >= p->context->conf->offload_limit and
        p->context->searches.items.size() > 0 )
    {
        if ( offloader->available() )
            return do_offload(p);

        pc.offload_busy++;
    }

    if ( p->flow ? p->flow->context_chain.front() : sw->non_flow_chain.front() )
    {
        // cppcheck-suppress unreadVariable
        Profile profile(mpsePerfStats);
        p->context->searches.search_sync();
        sw->suspend();
        pc.offload_suspends++;
        return true;
    }

    assert(p->flow ? !p->flow->is_suspended() : true);
    fp_complete(p, true);
    return false;
}

void DetectionEngine::idle()
{
    if (offloader)
    {
        while ( offloader->count() )
        {
            debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
                "(wire) %" PRIu64 " de::sleep\n", pc.analyzed_pkts);

            onload();
        }
        debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
            "(wire) %" PRIu64 " de::idle (r=%d)\n", pc.analyzed_pkts,
            offloader->count());

        offloader->stop();
    }
}

void DetectionEngine::onload(Flow* flow)
{
    if ( flow->is_suspended() )
        pc.onload_waits++;

    while ( flow->is_suspended() )
    {
        debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
            "(wire) %" PRIu64 " de::sleep\n", pc.analyzed_pkts);

        resume_ready_suspends(flow->context_chain); // FIXIT-M makes onload reentrant-safe
        onload();
    }
    assert(!offloader->on_hold(flow));
}

void DetectionEngine::onload()
{
    // cppcheck-suppress unreadVariable
    Profile profile(mpsePerfStats);
    Packet* p;

    while (offloader->count() and offloader->get(p))
    {
        debug_logf(detection_trace, TRACE_DETECTION_ENGINE, p,
            "%" PRIu64 " de::onload %" PRIu64 " (r=%d)\n",
            p->context->packet_number, p->context->context_num, offloader->count());

        p->clear_offloaded();

        const IpsContextChain& chain = p->flow ? p->flow->context_chain :
            Analyzer::get_switcher()->non_flow_chain;

        resume_ready_suspends(chain);
    }
}

void DetectionEngine::resume_ready_suspends(const IpsContextChain& chain)
{
    while ( chain.front() and !chain.front()->packet->is_offloaded() )
    {
#ifdef REG_TEST
        complete(chain.front()->packet);
#else
        resume(chain.front()->packet);
#endif
    }
}

void DetectionEngine::complete(Packet* p)
{
    debug_logf(detection_trace, TRACE_DETECTION_ENGINE, p,
        "%" PRIu64 " de::resume %" PRIu64 " (r=%d)\n",
        p->context->packet_number, p->context->context_num, offloader->count());

    ContextSwitcher* sw = Analyzer::get_switcher();
    sw->resume(p->context);

    if ( p->is_detection_enabled(p->packet_flags & PKT_FROM_CLIENT) )
        fp_complete(p);
}

void DetectionEngine::resume(Packet* p)
{
    complete(p);

    finish_inspect_with_latency(p); // FIXIT-L should latency be evaluated here?
    finish_inspect(p, true);
    finish_packet(p);

    if ( !p->is_rebuilt() )
    {
        // This happens here to ensure needed contexts are available ASAP as
        // not directly forwarding leads to deadlocking waiting on new contexts
        Analyzer::get_local_analyzer()->post_process_packet(p);
    }
}

void DetectionEngine::wait_for_context()
{
    ContextSwitcher* sw = Analyzer::get_switcher();

    if ( !sw->idle_count() )
    {
        pc.context_stalls++;
        do
        {
            onload();
        }
        // cppcheck-suppress knownConditionTrueFalse
        while ( !sw->idle_count() );
    }
}

//--------------------------------------------------------------------------
// detection / inspection
//--------------------------------------------------------------------------

bool DetectionEngine::detect(Packet* p, bool offload_ok)
{
    assert(p);

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
    case PktType::IP:
    case PktType::TCP:
    case PktType::UDP:
    case PktType::ICMP:
    case PktType::FILE:
    case PktType::USER:
        if ( offload_ok and p->flow )
            return offload(p);

        fp_full(p);
        break;

    default:
        break;
    }
    return false;
}

bool DetectionEngine::inspect(Packet* p)
{
    bool inspected = false;
    {
        PacketLatency::Context pkt_latency_ctx { p };

        InspectorManager::probe_first(p);
        if ( p->ptrs.decode_flags & DECODE_ERR_FLAGS )
        {
            if ( p->context->conf->ips_inline_mode() and
                snort::get_network_policy()->checksum_drops(p->ptrs.decode_flags &
                    DECODE_ERR_CKSUM_ALL) )
            {
                p->active->drop_packet(p);
            }
        }
        else
        {
            enable_content(p);

            InspectorManager::execute(p);
            inspected = true;

            if ( !all_disabled(p) )
            {
                if ( PacketTracer::is_daq_activated() )
                    PacketTracer::restart_timer();

                if ( detect(p, offload_enabled) )
                    return false; // don't finish out offloaded packets
            }
        }
        finish_inspect_with_latency(p);
    }
    finish_inspect(p, inspected);

    return true;
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

int DetectionEngine::queue_event(unsigned gid, unsigned sid)
{
    OptTreeNode* otn = OtnLookup(SnortConfig::get_conf()->otn_map, gid, sid);

    if ( !otn )
        return 0;

    SF_EVENTQ* pq = get_event_queue();
    EventNode* en = (EventNode*)sfeventq_event_alloc(pq);

    if ( !en )
        return -1;

    en->otn = otn;
    en->rtn = nullptr;  // lookup later after ips policy selection

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

        if ( !en->rtn || !en->rtn->enabled() )
            return 0;  // not enabled
    }

    fpLogEvent(en->rtn, en->otn, (Packet*)user);
    sfthreshold_reset();

    return 0;
}

/*
**  We return whether we logged events or not.  We've add a eventq user
**  structure so we can track whether the events logged were rule events
**  or builtin events.  The reason being that we don't want
**  to flush a TCP stream for builtin events, and cause
**  early flushing of the stream.
*/
int DetectionEngine::log_events(Packet* p)
{
    // cppcheck-suppress unreadVariable
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

