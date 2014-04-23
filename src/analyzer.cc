/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "analyzer.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>

#include <chrono>
#include <string>
#include <thread>
using namespace std;

#include "tag.h"
#include "thread.h"
#include "helpers/swapper.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "perf_monitor/perf.h"
#include "perf_monitor/perf_base.h"
#include "time/packet_time.h"
#include "flow/flow.h"
#include "flow/flow_control.h"
#include "stream5/stream_api.h"
#include "stream5/stream_common.h"
#include "stream5/stream_ha.h"
#include "events/event_queue.h"
#include "managers/inspector_manager.h"
#include "managers/packet_manager.h"
#include "file_api/file_service.h"
#include "detection/fpdetect.h"
#include "ips_options/replace.h"

#ifndef DLT_LANE8023
/*
 * Old OPEN BSD Log format is 17.
 * Define DLT_OLDPFLOG unless DLT_LANE8023 (Suse 6.3) is already
 * defined in bpf.h.
 */
#define DLT_OLDPFLOG 17
#endif

// non-local for easy access from core
static THREAD_LOCAL Packet s_packet;
static THREAD_LOCAL DAQ_PktHdr_t s_pkth;
static THREAD_LOCAL uint8_t s_data[65536];

static MainHook_f main_hook = Analyzer::ignore;

void Analyzer::set_main_hook(MainHook_f f)
{ main_hook = f; }

typedef DAQ_Verdict 
    (*PacketCallback)(void*, const DAQ_PktHdr_t*, const uint8_t*);

static DAQ_Verdict fail_open(void*, const DAQ_PktHdr_t*, const uint8_t*);
static DAQ_Verdict packet_callback(void*, const DAQ_PktHdr_t*, const uint8_t*);

static THREAD_LOCAL PacketCallback main_func = fail_open;

//-------------------------------------------------------------------------

Packet* get_current_packet()
{ return &s_packet; }

// FIXIT for multiple packet threads
// using thread locals for s_pkth and s_data won't work
// will need array of s_packet, s_pkth, and s_data and 
// capture all if it is not clear which thread crashed
void CapturePacket()
{
    if ( s_packet.pkth )
    {
        s_pkth = *s_packet.pkth;

        if ( s_packet.pkt )
            memcpy(s_data, s_packet.pkt, 0xFFFF & s_packet.pkth->caplen);
    }
}

void set_default_policy()
{
    set_network_policy(snort_conf->policy_map->network_policy[0]);
    set_ips_policy(snort_conf->policy_map->ips_policy[0]);
    set_inspection_policy(snort_conf->policy_map->inspection_policy[0]);
}

static void set_policy(Packet*)  // FIXIT implement based on bindings
{
#if 0
    int vlanId = (p->vh) ? VTH_VLAN(p->vh) : -1;
    snort_ip_p srcIp = (p->iph) ? GET_SRC_IP((p)) : (snort_ip_p)0;
    snort_ip_p dstIp = (p->iph) ? GET_DST_IP((p)) : (snort_ip_p)0;

    //set policy id for this packet
    setCurrentPolicy(snort_conf, sfGetApplicablePolicyId(
        snort_conf->policy_config, vlanId, srcIp, dstIp));
#else
    set_default_policy();
#endif
}

void DecodeRebuiltPacket (
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt, 
    Flow* lws)
{
    SnortEventqPush();
    PacketManager::decode(p, pkthdr, pkt);

    p->flow = lws;

    set_policy(p);
    p->user_policy_id = get_ips_policy()->user_policy_id;

    SnortEventqPop();
}

void DetectRebuiltPacket (Packet* p)
{
    int tmp_do_detect = do_detect;
    int tmp_do_detect_content = do_detect_content;

    SnortEventqPush();
    Inspect(p);
    SnortEventqPop();
    DetectReset((uint8_t *)p->data, p->dsize);

    do_detect = tmp_do_detect;
    do_detect_content = tmp_do_detect_content;
}

void LogRebuiltPacket (Packet* p)
{
    SnortEventqPush();
    SnortEventqLog(p);
    SnortEventqReset();
    SnortEventqPop();
}

DAQ_Verdict ProcessPacket(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt, void* ft)
{
    DAQ_Verdict verdict = DAQ_VERDICT_PASS;

    set_default_policy();

    PacketManager::decode(p, pkthdr, pkt);
    assert(p->pkth && p->pkt);

    if (ft)
    {
        p->packet_flags |= (PKT_PSEUDO | PKT_REBUILT_FRAG);
        p->pseudo_type = PSEUDO_PKT_IP;
        p->fragtracker = ft;
        Encode_SetPkt(p);
    }
    if ( !p->proto_bits )
        p->proto_bits = PROTO_BIT__OTHER;

    // required until decoders are fixed
    else if ( !p->family && (p->proto_bits & PROTO_BIT__IP) )
        p->proto_bits &= ~PROTO_BIT__IP;

#ifndef POLICY_BY_ID_ONLY
    set_policy(p);
#endif

    p->user_policy_id = get_ips_policy()->user_policy_id;

    /* just throw away the packet if we are configured to ignore this port */
    if ( !(p->packet_flags & PKT_IGNORE) )
        main_hook(p);

    if ( Active_SessionWasDropped() )
    {
        if ( !Active_PacketForceDropped() )
            Active_DropAction(p);
        else
            Active_ForceDropAction(p);

        if ( Active_GetTunnelBypass() )
        {
            pc.internal_blacklist++;
            return verdict;
        }

        if ( ScInlineMode() || Active_PacketForceDropped() )
            verdict = DAQ_VERDICT_BLACKLIST;
        else
            verdict = DAQ_VERDICT_IGNORE;
    }

    return verdict;
}

// FIXIT need to call fail open from a different thread
static DAQ_Verdict fail_open(
    void*, const DAQ_PktHdr_t*, const uint8_t*)
{
    pc.total_fail_open++;
    return DAQ_VERDICT_PASS;
}

static DAQ_Verdict packet_callback(
    void*, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    int inject = 0;
    DAQ_Verdict verdict = DAQ_VERDICT_PASS;
    PROFILE_VARS;

    PREPROC_PROFILE_START(totalPerfStats);

    pc.total_from_daq++;

    /* Increment counter that we're evaling rules for caching results */
    rule_eval_pkt_count++;

    /* Save off the time of each and every packet */
    packet_time_update(&pkthdr->ts);

    if ( snort_conf->pkt_skip && pc.total_from_daq <= snort_conf->pkt_skip )
    {
        PREPROC_PROFILE_END(totalPerfStats);
        return verdict;
    }

    /* reset the thresholding subsystem checks for this packet */
    sfthreshold_reset();

    PREPROC_PROFILE_START(eventqPerfStats);
    SnortEventqReset();
    Replace_ResetQueue();
    Active_ResetQueue();
    PREPROC_PROFILE_END(eventqPerfStats);

    verdict = ProcessPacket(&s_packet, pkthdr, pkt, NULL);

    if ( Active_ResponseQueued() )
    {
        Active_SendResponses(&s_packet);
    }
    if ( Active_PacketWasDropped() )
    {
        if ( verdict == DAQ_VERDICT_PASS )
            verdict = DAQ_VERDICT_BLOCK;
    }
    else
    {
        Replace_ModifyPacket(&s_packet);

        if ( s_packet.packet_flags & PKT_MODIFIED )
        {
            // this packet was normalized and/or has replacements
            Encode_Update(&s_packet);
            verdict = DAQ_VERDICT_REPLACE;
        }
        else if ( s_packet.packet_flags & PKT_RESIZED )
        {
            // we never increase, only trim, but
            // daq doesn't support resizing wire packet
            if ( !DAQ_Inject(s_packet.pkth, 0, s_packet.pkt, s_packet.pkth->pktlen) )
            {
                verdict = DAQ_VERDICT_BLOCK;
                inject = 1;
            }
        }
        else
        {
            if ( (s_packet.packet_flags & PKT_IGNORE) ||
                (stream.get_ignore_direction(s_packet.flow) == SSN_DIR_BOTH) )
            {
                if ( !Active_GetTunnelBypass() )
                {
                    verdict = DAQ_VERDICT_WHITELIST;
                }
                else
                {
                    verdict = DAQ_VERDICT_PASS;
                    pc.internal_whitelist++;
                }
            }
            else if ( s_packet.packet_flags & PKT_TRUST )
            {
                stream.set_ignore_direction(s_packet.flow, SSN_DIR_BOTH);

                verdict = DAQ_VERDICT_WHITELIST;
            }
            else
            {
                verdict = DAQ_VERDICT_PASS;
            }
        }
    }

    // This needs to be called here since the session could
    // have been updated anywhere up to this point. :( 
    ha_process(s_packet.flow);

    /* Collect some "on the wire" stats about packet size, etc */
    UpdateWireStats(&sfBase, pkthdr->caplen, Active_PacketWasDropped(), inject);
    Active_Reset();
    Encode_Reset();

    if ( flow_con )  // FIXIT always instantiate
        flow_con->timeout_flows(4, pkthdr->ts.tv_sec);

#if 0
    // FIXIT do this when idle
    if ( flow_con ) // FIXIT always instantiate
        flow_con->timeout_flows(16384, time(NULL));
#endif

    s_packet.pkth = NULL;  // no longer avail on segv

    PREPROC_PROFILE_END(totalPerfStats);
    return verdict;
}

static void snort_thread_init(const char* intf)
{
    // FIXIT the start-up sequence is a little off due to dropping privs
    DAQ_New(snort_conf, intf);
    DAQ_Start();

    PacketManager::set_grinder();

    // perfmon, for one, opens a log file for writing here
    InspectorManager::post_config(snort_conf);

    FileAPIPostInit();
    Encode_Init();

    // this depends on instantiated daq capabilities
    // so it is done here instead of SnortInit()
    Active_Init(snort_conf);

    SnortEventqNew(snort_conf->event_queue_config);

    InitTag();

    EventTrace_Init();
    detection_filter_init(snort_conf->detection_filter_config);

    otnx_match_data_init(snort_conf->num_rule_types);
}

static void snort_thread_term()
{
    if ( DAQ_WasStarted() )
        DAQ_Stop();

    DAQ_Delete();

    if ( snort_conf->dirty_pig )
        return;

#ifdef PERF_PROFILING
    ReleasePreprocStats();
#endif

    otnx_match_data_term();
    detection_filter_term();
    EventTrace_Term();
    CleanupTag();

    SnortEventqFree();
    Active_Term();
    Encode_Term();
}

//-------------------------------------------------------------------------
// from thread.h

// FIXIT instance_id zero indicates main thread during parse time and the
// first packet thread during runtime.  not sure if i'm ok with that.
// works for now.
static THREAD_LOCAL unsigned instance_id = 0;

unsigned get_instance_id()
{
    return instance_id;
}

unsigned get_instance_max()
{
    return snort_conf->max_threads;
}

const char* get_instance_file(string& file, const char* name)
{
    char id[8];
    snprintf(id, sizeof(id), "/%u/", get_instance_id());

    file = snort_conf->log_dir ? snort_conf->log_dir : "./";
    file += id;

    struct stat s;

    if ( stat(file.c_str(), &s) )
        // FIXIT getting random 0750 or 0700 (umask not thread local)?
        mkdir(file.c_str(), 0770);

    file += name;

    return file.c_str();
}

//-------------------------------------------------------------------------
// analyzer
//-------------------------------------------------------------------------

Analyzer::Analyzer(const char* s)
{
    done = false;
    count = 0;
    source = s;
    command = AC_NONE;
    swap = nullptr;
}

void Analyzer::operator()(unsigned id, Swapper* ps)
{
    instance_id = id;
    ps->apply();

    snort_thread_init(source);
    InspectorManager::thread_init(snort_conf, instance_id);

    main_func = packet_callback;

    analyze();

    InspectorManager::thread_term(snort_conf);
    snort_thread_term();

    delete ps;
    done = true;
}

bool Analyzer::handle(AnalyzerCommand ac)
{
    switch ( ac )
    {
    case AC_STOP:
        return false;

    case AC_PAUSE:
        {
            chrono::seconds sec(1);
            this_thread::sleep_for(sec);
        }
        break;

    case AC_RESUME:
        break;

    case AC_ROTATE:
        SetRotatePerfFileFlag();
        break;

    case AC_SWAP:
        if ( swap )
        {
            swap->apply();
            swap = nullptr;
        }
        break;

    default:
        break;
    }
    return true;
}

void Analyzer::analyze()
{
    uint64_t max = snort_conf->pkt_cnt;

    while ( true )
    {
        if ( command )
        {
            if ( !handle(command) )
                break;

            if ( command == AC_PAUSE )
                continue;

            command = AC_NONE;
        }
        if ( DAQ_Acquire(1, main_func, NULL) )
            break;

        ++count;

        if ( max && count >= max )
            break;
    }
}

