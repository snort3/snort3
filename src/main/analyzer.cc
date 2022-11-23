//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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
// analyzer.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "analyzer.h"

#include <daq.h>

#include <thread>

#include "detection/context_switcher.h"
#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "detection/ips_context.h"
#include "detection/tag.h"
#include "file_api/file_service.h"
#include "filters/detection_filter.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "filters/sfthreshold.h"
#include "flow/flow.h"
#include "flow/ha.h"
#include "framework/data_bus.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency.h"
#include "log/messages.h"
#include "main/swapper.h"
#include "main.h"
#include "managers/action_manager.h"
#include "managers/inspector_manager.h"
#include "managers/ips_manager.h"
#include "managers/event_manager.h"
#include "managers/module_manager.h"
#include "memory/memory_cap.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_module.h"
#include "packet_tracer/packet_tracer.h"
#include "profiler/profiler.h"
#include "pub_sub/daq_message_event.h"
#include "pub_sub/finalize_packet_event.h"
#include "side_channel/side_channel.h"
#include "stream/stream.h"
#include "target_based/host_attributes.h"
#include "time/packet_time.h"
#include "trace/trace_api.h"
#include "utils/stats.h"

#include "analyzer_command.h"
#include "oops_handler.h"
#include "snort.h"
#include "snort_config.h"
#include "thread_config.h"

using namespace snort;
using namespace std;

static MainHook_f main_hook = snort_ignore;

THREAD_LOCAL ProfileStats daqPerfStats;
static THREAD_LOCAL Analyzer* local_analyzer = nullptr;

//-------------------------------------------------------------------------

class RetryQueue
{
    struct Entry
    {
        Entry(const struct timeval& next_try, DAQ_Msg_h msg) : next_try(next_try), msg(msg) { }

        struct timeval next_try;
        DAQ_Msg_h msg;
    };

public:
    RetryQueue(unsigned interval_ms)
    {
        assert(interval_ms > 0);
        interval = { static_cast<time_t>(interval_ms / 1000), static_cast<suseconds_t>((interval_ms % 1000) * 1000) };
    }

    ~RetryQueue()
    {
        assert(empty());
    }

    void put(DAQ_Msg_h msg)
    {
        struct timeval now, next_try;
        packet_gettimeofday(&now);
        timeradd(&now, &interval, &next_try);
        queue.emplace_back(next_try, msg);
    }

    DAQ_Msg_h get(const struct timeval* now = nullptr)
    {
        if (!empty())
        {
            const Entry& entry = queue.front();
            if (!now || !timercmp(now, &entry.next_try, <))
            {
                DAQ_Msg_h msg = entry.msg;
                queue.pop_front();
                return msg;
            }
        }
        return nullptr;
    }

    bool empty() const
    {
        return queue.empty();
    }

private:
    deque<Entry> queue;
    struct timeval interval;
};

//-------------------------------------------------------------------------

/*
 * Static Class Methods
 */
Analyzer* Analyzer::get_local_analyzer()
{
    return local_analyzer;
}

ContextSwitcher* Analyzer::get_switcher()
{
    assert(local_analyzer != nullptr);
    return local_analyzer->switcher;
}

void Analyzer::set_main_hook(MainHook_f f)
{
    main_hook = f;
}

//-------------------------------------------------------------------------
// message processing
//-------------------------------------------------------------------------

static void process_daq_sof_eof_msg(DAQ_Msg_h msg, DAQ_Verdict& verdict)
{
    const DAQ_FlowStats_t *stats = (const DAQ_FlowStats_t*) daq_msg_get_hdr(msg);
    const char* key;

    select_default_policy(*stats, SnortConfig::get_conf());
    if (daq_msg_get_type(msg) == DAQ_MSG_TYPE_EOF)
    {
        packet_time_update(&stats->eof_timestamp);
        daq_stats.eof_messages++;
        key = DAQ_EOF_MSG_EVENT;
    }
    else
    {
        packet_time_update(&stats->sof_timestamp);
        daq_stats.sof_messages++;
        key = DAQ_SOF_MSG_EVENT;
    }

    DaqMessageEvent event(msg, verdict);
    DataBus::publish(key, event);
}

static bool process_packet(Packet* p)
{
    assert(p->pkth && p->pkt);

    daq_stats.rx_bytes += p->pktlen;

    PacketTracer::activate(*p);

    p->user_inspection_policy_id = get_inspection_policy()->user_policy_id;
    p->user_ips_policy_id = get_ips_policy()->user_policy_id;
    p->user_network_policy_id = get_network_policy()->user_policy_id;

    if ( !(p->packet_flags & PKT_IGNORE) )
    {
        clear_file_data();
        // return incomplete status if the main hook indicates not all work was done
        if (!main_hook(p))
            return false;
    }

    return true;
}

static inline bool is_sticky_verdict(const DAQ_Verdict verdict)
{
    return verdict == DAQ_VERDICT_WHITELIST or verdict == DAQ_VERDICT_BLACKLIST
        or verdict == DAQ_VERDICT_IGNORE;
}

// Finalize DAQ message verdict
static DAQ_Verdict distill_verdict(Packet* p)
{
    if ( p->flow and is_sticky_verdict(p->flow->last_verdict) )
        return p->flow->last_verdict;

    DAQ_Verdict verdict = DAQ_VERDICT_PASS;
    Active* act = p->active;

    // First Pass
    if ( act->session_was_blocked() ||
            (p->flow && (p->flow->flow_state == Flow::FlowState::BLOCK)) )
    {
        if ( !act->can_act() )
            verdict = DAQ_VERDICT_PASS;
        else if ( act->get_tunnel_bypass() )
        {
            daq_stats.internal_blacklist++;
            verdict = DAQ_VERDICT_BLOCK;
        }
        else if ( p->context->conf->inline_mode() || act->packet_force_dropped() )
            verdict = DAQ_VERDICT_BLACKLIST;
        else
            verdict = DAQ_VERDICT_IGNORE;
    }

    // Second Pass, now with more side effects
    if ( act->packet_was_dropped() && act->can_act() )
    {
        if ( verdict == DAQ_VERDICT_PASS )
            verdict = DAQ_VERDICT_BLOCK;
    }
    else if ( p->packet_flags & PKT_RESIZED )
    {
        // we never increase, only trim, but daq doesn't support resizing wire packet
        PacketManager::encode_update(p);

        if ( p->daq_instance->inject(p->daq_msg, 0, p->pkt, p->pktlen) == DAQ_SUCCESS )
            verdict = DAQ_VERDICT_BLOCK;
        // FIXIT-M X Should we be blocking the wire packet even if the injection fails?
    }
    else if ( p->packet_flags & PKT_MODIFIED )
    {
        // this packet was normalized and/or has replacements
        PacketManager::encode_update(p);
        verdict = DAQ_VERDICT_REPLACE;
    }
    else if ( act->session_was_trusted() )
        verdict = DAQ_VERDICT_WHITELIST;
    else if ( (p->packet_flags & PKT_IGNORE) ||
        (p->flow &&
            (p->flow->get_ignore_direction() == SSN_DIR_BOTH ||
                p->flow->flow_state == Flow::FlowState::ALLOW)) )
    {
        verdict = DAQ_VERDICT_WHITELIST;
    }
    else if ( p->ptrs.decode_flags & DECODE_PKT_TRUST )
    {
        if ( p->flow )
            p->flow->set_ignore_direction(SSN_DIR_BOTH);
        verdict = DAQ_VERDICT_WHITELIST;
    }
    else
        verdict = DAQ_VERDICT_PASS;

    if (DAQ_VERDICT_WHITELIST == verdict)
    {
        if (p->flow && p->flow->cannot_trust())
            verdict = DAQ_VERDICT_PASS;
        else if (act->get_tunnel_bypass())
        {
            verdict = DAQ_VERDICT_PASS;
            daq_stats.internal_whitelist++;
        }
    }

    if ( p->flow )
        p->flow->last_verdict = verdict;

    return verdict;
}

static void packet_trace_dump(Packet* p, DAQ_Verdict verdict, bool msg_was_held)
{
    PacketTracer::log("Policies: Network %u, Inspection %u, Detection %u\n",
        get_network_policy()->user_policy_id, get_inspection_policy()->user_policy_id,
        get_ips_policy()->user_policy_id);

    if (p->active->packet_retry_requested())
        PacketTracer::log("Verdict: Queuing for Retry\n");
    else if (msg_was_held)
        PacketTracer::log("Verdict: Holding for Detection\n");
    else
        PacketTracer::log("Verdict: %s\n", SFDAQ::verdict_to_string(verdict));
    PacketTracer::dump(p);
}

void Analyzer::add_to_retry_queue(DAQ_Msg_h daq_msg, Flow* flow)
{
    retry_queue->put(daq_msg);
    if (flow)
        flow->flags.retry_queued = true;
}

/*
 * Private message processing methods
 */
void Analyzer::post_process_daq_pkt_msg(Packet* p)
{
    bool msg_was_held = false;

    Active::execute(p);

    DAQ_Verdict verdict = MAX_DAQ_VERDICT;

    if (p->active->packet_retry_requested())
    {
        add_to_retry_queue(p->daq_msg, p->flow);
        daq_stats.retries_queued++;
    }
    else
    {
        msg_was_held = (p->active->is_packet_held() and Stream::set_packet_action_to_hold(p));
        if (msg_was_held)
        {
            if (p->flow->flags.trigger_detained_packet_event)
            {
                DataBus::publish(DETAINED_PACKET_EVENT, p);
            }
        }
        else
            verdict = distill_verdict(p);
    }

    HighAvailabilityManager::process_update(p->flow, p);

    if (verdict != MAX_DAQ_VERDICT)
    {
        // Publish an event if something has indicated that it wants the
        // finalize event on this flow.
        if (p->flow and p->flow->flags.trigger_finalize_event)
        {
            FinalizePacketEvent event(p, verdict);
            DataBus::publish(FINALIZE_PACKET_EVENT, event);
        }

        if (PacketTracer::is_active())
            packet_trace_dump(p, verdict, msg_was_held);

        if (PacketTracer::is_daq_activated())
            PacketTracer::daq_dump(p);

        if (verdict == DAQ_VERDICT_BLOCK or verdict == DAQ_VERDICT_BLACKLIST)
            p->active->send_reason_to_daq(*p);

        oops_handler->set_current_message(nullptr);
        p->pkth = nullptr;  // No longer avail after finalize_message.

        {
            Profile profile(daqPerfStats);
            p->daq_instance->finalize_message(p->daq_msg, verdict);
        }
    }
    else
    {
        if (PacketTracer::is_active())
            packet_trace_dump(p, verdict, msg_was_held);

        if (PacketTracer::is_daq_activated())
            PacketTracer::daq_dump(p);
    }
}

void Analyzer::process_daq_pkt_msg(DAQ_Msg_h msg, bool retry)
{
    const DAQ_PktHdr_t* pkthdr = daq_msg_get_pkthdr(msg);

    pc.analyzed_pkts++;

    if (!retry)
        packet_time_update(&pkthdr->ts);

    DetectionEngine::wait_for_context();
    switcher->start();

    Packet* p = switcher->get_context()->packet;
    p->context->wire_packet = p;
    p->context->packet_number = get_packet_number();
    select_default_policy(*pkthdr, p->context->conf);

    DetectionEngine::reset();
    sfthreshold_reset();
    Active::clear_queue(p);

    p->daq_msg = msg;
    p->daq_instance = daq_instance;

    PacketManager::decode(p, pkthdr, daq_msg_get_data(msg), daq_msg_get_data_len(msg), false, retry);

    if (process_packet(p))
    {
        post_process_daq_pkt_msg(p);
        switcher->stop();
    }

    // Beyond this point, we don't have an active context, but e.g. calls to
    // get_current_packet() or get_current_wire_packet() require a context.
    // We must ensure that a context is available when one is needed.
    Stream::handle_timeouts(false);
    HighAvailabilityManager::process_receive();
}

void Analyzer::process_daq_msg(DAQ_Msg_h msg, bool retry)
{
    oops_handler->set_current_message(msg);
    memory::MemoryCap::free_space();

    DAQ_Verdict verdict = DAQ_VERDICT_PASS;
    switch (daq_msg_get_type(msg))
    {
        case DAQ_MSG_TYPE_PACKET:
            process_daq_pkt_msg(msg, retry);
            // process_daq_pkt_msg() handles finalizing the message (or tracking it if offloaded)
            return;
        case DAQ_MSG_TYPE_SOF:
        case DAQ_MSG_TYPE_EOF:
            process_daq_sof_eof_msg(msg, verdict);
            break;
        default:
            {
                daq_stats.other_messages++;
                DaqMessageEvent event(msg, verdict);
                DataBus::publish(DAQ_OTHER_MSG_EVENT, event);
            }
            break;
    }
    oops_handler->set_current_message(nullptr);
    {
        Profile profile(daqPerfStats);
        daq_instance->finalize_message(msg, verdict);
    }
}

void Analyzer::process_retry_queue()
{
    if (!retry_queue->empty())
    {
        struct timeval now;
        packet_gettimeofday(&now);
        DAQ_Msg_h msg;

        while ((msg = retry_queue->get(&now)) != nullptr)
        {
            process_daq_msg(msg, true);
            daq_stats.retries_processed++;
        }
    }
}

/*
 * Public packet processing methods
 */
bool Analyzer::inspect_rebuilt(Packet* p)
{
    DetectionEngine de;
    return main_hook(p);
}

bool Analyzer::process_rebuilt_packet(Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt,
    uint32_t pktlen)
{
    PacketManager::decode(p, pkthdr, pkt, pktlen, true);

    p->packet_flags |= (PKT_PSEUDO | PKT_REBUILT_FRAG);
    p->pseudo_type = PSEUDO_PKT_IP;

    return process_packet(p);
}

void Analyzer::post_process_packet(Packet* p)
{
    post_process_daq_pkt_msg(p);
    // FIXIT-? There is an assumption that this is being called on the active context...
    switcher->stop();
}

void Analyzer::finalize_daq_message(DAQ_Msg_h msg, DAQ_Verdict verdict)
{
    Profile profile(daqPerfStats);
    daq_instance->finalize_message(msg, verdict);
}

//-------------------------------------------------------------------------
// Utility
//-------------------------------------------------------------------------

void Analyzer::show_source()
{
    const char* pcap = source.c_str();

    if (!strcmp(pcap, "-"))
        pcap = "stdin";

    if (get_run_num() != 1)
        fprintf(stdout, "%s", "\n");

    fprintf(stdout, "Reading network traffic from \"%s\" with snaplen = %u\n",
        pcap, SnortConfig::get_conf()->daq_config->get_mru_size());
}

void Analyzer::set_state(State s)
{
    state = s;
    main_poke(id);
}

const char* Analyzer::get_state_string()
{
    State s = get_state();  // can't use atomic in switch with optimization

    switch ( s )
    {
        case State::NEW:         return "NEW";
        case State::INITIALIZED: return "INITIALIZED";
        case State::STARTED:     return "STARTED";
        case State::RUNNING:     return "RUNNING";
        case State::PAUSED:      return "PAUSED";
        case State::STOPPED:     return "STOPPED";
        default: assert(false);
    }

    return "UNKNOWN";
}

//-------------------------------------------------------------------------
// Thread life cycle
//-------------------------------------------------------------------------

void Analyzer::idle()
{
    idling = true;

    // FIXIT-L this whole thing could be pub-sub
    daq_stats.idle++;

    // This should only be called if the DAQ timeout elapsed, so increment the packet time
    // by the DAQ timeout.
    struct timeval now, increment;
    unsigned int timeout = SnortConfig::get_conf()->daq_config->timeout;
    packet_gettimeofday(&now);
    increment = { static_cast<time_t>(timeout / 1000), static_cast<suseconds_t>((timeout % 1000) * 1000) };
    timeradd(&now, &increment, &now);
    packet_time_update(&now);

    DataBus::publish(THREAD_IDLE_EVENT, nullptr);

    // Service the retry queue with the new packet time.
    process_retry_queue();

    Stream::handle_timeouts(true);

    HighAvailabilityManager::process_receive();

    handle_uncompleted_commands();

    idling = false;
}

/*
 * Perform all packet thread initialization actions that can be taken with dropped privileges
 * and/or must be called after the DAQ module has been started.
 */
void Analyzer::init_unprivileged()
{
    // using dummy values until further integration
    // FIXIT-M max_contexts must be <= DAQ msg pool to avoid permanent stall (offload only)
    // condition (polling for packets that won't come to resume ready suspends)
#ifdef REG_TEST
    const unsigned max_contexts = 20;
#else
    const unsigned max_contexts = 255;
#endif

    switcher = new ContextSwitcher;

    for ( unsigned i = 0; i < max_contexts; ++i )
        switcher->push(new IpsContext);

    const SnortConfig* sc = SnortConfig::get_conf();

    // This should be called as soon as possible
    // to handle all trace log messages
    TraceApi::thread_init(sc->trace_config);

    CodecManager::thread_init(sc);

    // this depends on instantiated daq capabilities
    // so it is done here instead of init()
    Active::thread_init(sc);

    InitTag();
    EventTrace_Init();

    EventManager::open_outputs();
    IpsManager::setup_options(sc);
    ActionManager::thread_init(sc);
    FileService::thread_init();
    SideChannelManager::thread_init();
    HighAvailabilityManager::thread_init(); // must be before InspectorManager::thread_init();
    InspectorManager::thread_init(sc);
    PacketTracer::thread_init();
    HostAttributesManager::initialize();

    // in case there are HA messages waiting, process them first
    HighAvailabilityManager::process_receive();
    PacketManager::thread_init();

    // init filters hash tables that depend on alerts
    sfthreshold_alloc(sc->threshold_config->memcap, sc->threshold_config->memcap);
    SFRF_Alloc(sc->rate_filter_config->memcap);
}

void Analyzer::reinit(const SnortConfig* sc)
{
    InspectorManager::thread_reinit(sc);
    ActionManager::thread_reinit(sc);
    TraceApi::thread_reinit(sc->trace_config);
    EventManager::reload_outputs();
}

void Analyzer::stop_removed(const SnortConfig* sc)
{
    InspectorManager::thread_stop_removed(sc);
}

void Analyzer::term()
{
    const SnortConfig* sc = SnortConfig::get_conf();

    HighAvailabilityManager::thread_term_beginning();

    if ( !sc->dirty_pig )
        Stream::purge_flows();

    DAQ_Msg_h msg;
    while ((msg = retry_queue->get()) != nullptr)
    {
        daq_stats.retries_discarded++;
        Profile profile(daqPerfStats);
        daq_instance->finalize_message(msg, DAQ_VERDICT_BLOCK);
    }

    DetectionEngine::idle();
    InspectorManager::thread_stop(sc);
    InspectorManager::thread_term();
    ModuleManager::accumulate("memory");
    ActionManager::thread_term();

    IpsManager::clear_options(sc);
    EventManager::close_outputs();
    CodecManager::thread_term();
    HighAvailabilityManager::thread_term();
    SideChannelManager::thread_term();

    oops_handler->set_current_message(nullptr);

    daq_instance->stop();
    SFDAQ::set_local_instance(nullptr);

    PacketLatency::tterm();
    RuleLatency::tterm();

    Profiler::consolidate_stats();

    DetectionEngine::thread_term();
    EventTrace_Term();
    CleanupTag();
    FileService::thread_term();
    PacketTracer::thread_term();
    PacketManager::thread_term();

    Active::thread_term();
    delete switcher;

    sfthreshold_free();
    RateFilter_Cleanup();

    TraceApi::thread_term();

    ModuleManager::accumulate_module("memory");
}

Analyzer::Analyzer(SFDAQInstance* instance, unsigned i, const char* s, uint64_t msg_cnt)
{
    id = i;
    exit_after_cnt = msg_cnt;
    source = s ? s : "";
    daq_instance = instance;
    oops_handler = new OopsHandler();
    retry_queue = new RetryQueue(200);
    set_state(State::NEW);
}

Analyzer::~Analyzer()
{
    delete daq_instance;
    delete oops_handler;
    delete retry_queue;
}

void Analyzer::operator()(Swapper* ps, uint16_t run_num)
{
    oops_handler->tinit();

    set_thread_type(STHREAD_TYPE_PACKET);
    set_instance_id(id);
    set_run_num(run_num);
    local_analyzer = this;

    ps->apply(*this);

    if (SnortConfig::get_conf()->pcap_show())
        show_source();

    // init here to pin separately from packet threads
    DetectionEngine::thread_init();

    // Perform all packet thread initialization actions that need to be taken with escalated
    // privileges prior to starting the DAQ module.
    SnortConfig::get_conf()->thread_config->implement_thread_affinity(
        STHREAD_TYPE_PACKET, get_instance_id());

    SFDAQ::set_local_instance(daq_instance);
    set_state(State::INITIALIZED);

    Profiler::start();

    // Start the main loop
    analyze();

    Profiler::stop(pc.analyzed_pkts);
    term();

    set_state(State::STOPPED);

    oops_handler->tterm();
}

/* Note: This will be called from the main thread.  Everything it does must be
    thread-safe in relation to interactions with the analyzer thread. */
void Analyzer::execute(AnalyzerCommand* ac)
{
    pending_work_queue_mutex.lock();
    pending_work_queue.push(ac);
    pending_work_queue_mutex.unlock();

    /* Break out of the DAQ acquire loop so that the command will be processed.
        This is explicitly safe to call from another thread. */
    if ( state >= State::STARTED and state < State::STOPPED and daq_instance )
        daq_instance->interrupt();
}

bool Analyzer::handle_command()
{
    AnalyzerCommand* ac = nullptr;

    pending_work_queue_mutex.lock();
    if (!pending_work_queue.empty())
    {
        ac = pending_work_queue.front();
        pending_work_queue.pop();
    }
    pending_work_queue_mutex.unlock();

    if (!ac)
        return false;

    void* ac_state = nullptr;
    if ( ac->need_update_reload_id() )
        SnortConfig::update_thread_reload_id();

    if ( ac->execute(*this, &ac_state) )
        add_command_to_completed_queue(ac);
    else
        add_command_to_uncompleted_queue(ac, ac_state);

    return true;
}

void Analyzer::add_command_to_uncompleted_queue(AnalyzerCommand* aci, void* acs)
{
    UncompletedAnalyzerCommand* cac = new UncompletedAnalyzerCommand(aci, acs);

    uncompleted_work_queue.push_back(cac);
}

void Analyzer::add_command_to_completed_queue(AnalyzerCommand* ac)
{
        completed_work_queue_mutex.lock();
        completed_work_queue.push(ac);
        completed_work_queue_mutex.unlock();
}

void Analyzer::handle_commands()
{
    while (handle_command())
        ;
}

void Analyzer::handle_uncompleted_commands()
{
    std::list<UncompletedAnalyzerCommand*>::iterator it = uncompleted_work_queue.begin();
    while (it != uncompleted_work_queue.end() )
    {
        UncompletedAnalyzerCommand* cac = *it;

        if (cac->command->execute(*this, &cac->state) )
        {
            add_command_to_completed_queue(cac->command);
            it = uncompleted_work_queue.erase(it);
            delete cac;
        }
        else
            ++it;
    }
}

DAQ_RecvStatus Analyzer::process_messages()
{
    // Max receive becomes the minimum of the configured batch size, the remaining exit_after
    // count (if requested), and the remaining pause_after count (if requested).
    unsigned max_recv = daq_instance->get_batch_size();
    if (exit_after_cnt && exit_after_cnt < max_recv)
        max_recv = exit_after_cnt;
    if (pause_after_cnt && pause_after_cnt < max_recv)
        max_recv = pause_after_cnt;

    DAQ_RecvStatus rstat;
    {
        Profile profile(daqPerfStats);
        rstat = daq_instance->receive_messages(max_recv);
    }

    // Preemptively service available onloads to potentially unblock processing the first message.
    // This conveniently handles servicing offloads in the no messages received case as well.
    DetectionEngine::onload();

    unsigned num_recv = 0;
    DAQ_Msg_h msg;
    while ((msg = daq_instance->next_message()) != nullptr)
    {
        // Dispose of any messages to be skipped first.
        if (skip_cnt > 0)
        {
            Profile profile(daqPerfStats);
            daq_stats.skipped++;
            skip_cnt--;
            daq_instance->finalize_message(msg, DAQ_VERDICT_PASS);
            continue;
        }
        // FIXIT-M reimplement fail-open capability?
        num_recv++;
        // IMPORTANT: process_daq_msg() is responsible for finalizing the messages.
        process_daq_msg(msg, false);
        DetectionEngine::onload();
        process_retry_queue();
        handle_uncompleted_commands();
    }

    if (exit_after_cnt && (exit_after_cnt -= num_recv) == 0)
        stop();
    if (pause_after_cnt && (pause_after_cnt -= num_recv) == 0)
        pause();
    return rstat;
}

void Analyzer::analyze()
{
    while (!exit_requested)
    {
        // If we're not in the running state (usually either pre-start or paused),
        // just keep stalling until something else comes up.
        if (state != State::RUNNING)
        {
            if (!handle_command())
            {
                chrono::milliseconds ms(10);
                this_thread::sleep_for(ms);
            }
            continue;
        }

        // Receive and process a batch of messages.  Evaluate the receive status after processing
        // the returned messages to determine if we should immediately continue, take the opportunity
        // to deal with some house cleaning work, or terminate the analyzer thread.
        DAQ_RecvStatus rstat = process_messages();
        if (rstat != DAQ_RSTAT_OK && rstat != DAQ_RSTAT_WOULD_BLOCK)
        {
            if (rstat == DAQ_RSTAT_TIMEOUT)
            {
                // If the receive timed out, let's do some idle work before continuing.
                // FIXIT-L Hitting a one second timeout when attached to any real traffic source
                // is extremely unlikely, so relying on anything in thread_idle() ever being
                // called is dangerous.
                idle();
            }
            else if (rstat == DAQ_RSTAT_INTERRUPTED)
            {
                // If the status reports INTERRUPTED because of an interrupt() call, exit_requested should
                // be set for the next pass through the main loop.  Use this as a hint to check for analyzer
                // commands.
                handle_commands();
            }
            else
            {
                if (rstat == DAQ_RSTAT_NOBUF)
                    ErrorMessage("Exhausted the DAQ message pool!\n");
                else if (rstat == DAQ_RSTAT_ERROR)
                    ErrorMessage("Error receiving message from the DAQ instance: %s\n", daq_instance->get_error());
                // Implicitly handled:
                // DAQ_RSTAT_EOF - File readback completed, job well done; let's get out of here.
                // DAQ_RSTAT_INVALID - This really shouldn't happen.
                break;
            }
        }
    }
}

void Analyzer::start()
{
    assert(state == State::INITIALIZED);

    if (!daq_instance->start())
    {
        ErrorMessage("Analyzer: Failed to start DAQ instance\n");
        exit_requested = true;
    }
    set_state(State::STARTED);
}

void Analyzer::run(bool paused)
{
    assert(state == State::STARTED);
    init_unprivileged();
    if ( paused )
        set_state(State::PAUSED);
    else
        set_state(State::RUNNING);
}

void Analyzer::stop()
{
    exit_requested = true;
}

void Analyzer::pause()
{
    if (state == State::RUNNING)
    {
        set_state(State::PAUSED);
        LogMessage("== [%u] paused\n", id);
    }
    else
        ErrorMessage("Analyzer: Received PAUSE command while in state %s\n",
            get_state_string());
}

void Analyzer::resume(uint64_t msg_cnt)
{
    if (state == State::PAUSED)
    {
        set_pause_after_cnt(msg_cnt);
        set_state(State::RUNNING);
    }
    else
        ErrorMessage("Analyzer: Received RESUME command while in state %s\n",
            get_state_string());
}

void Analyzer::reload_daq()
{
    if (daq_instance)
        daq_instance->reload();
}

void Analyzer::rotate()
{
    DataBus::publish(THREAD_ROTATE_EVENT, nullptr);
}

