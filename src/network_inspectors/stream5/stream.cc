/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "snort.h"
#include "snort_debug.h"
#include "stream5/stream_api.h"
#include "framework/inspector.h"
#include "flow/flow_control.h"
#include "stream5/stream_common.h"
#include "stream5/stream_global.h"
#include "stream5/stream_tcp.h"
#include "stream5/stream_udp.h"
#include "stream5/stream_icmp.h"
#include "stream5/stream_ip.h"
#include "stream5/stream_ha.h"
#include "profiler.h"

//-------------------------------------------------------------------------
// default limits
//-------------------------------------------------------------------------

static constexpr unsigned K = 1024;

// FIXIT redefined here; shouldn't need to init common with it
#define S5_DEFAULT_MEMCAP 8388608  /* 8MB */

#define S5_DEFAULT_MAX_TCP_SESSIONS  (256*K)
#define S5_DEFAULT_MAX_UDP_SESSIONS  (128*K)
#define S5_DEFAULT_MAX_ICMP_SESSIONS ( 64*K)
#define S5_DEFAULT_MAX_IP_SESSIONS   ( 16*K)

#define S5_DEFAULT_PRUNING_TIMEOUT    30
#define S5_DEFAULT_NOMINAL_TIMEOUT   180

//-------------------------------------------------------------------------
// globals
//-------------------------------------------------------------------------

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats s5PerfStats;

static PreprocStats* s5_get_profile(const char* key)
{
    if ( !strcmp(key, "stream5") )
        return &s5PerfStats;

    return nullptr;
}
#endif

static Stream5Stats gs5stats;
THREAD_LOCAL Stream5Stats s5stats;
THREAD_LOCAL FlowControl* flow_con = nullptr;  // FIXIT global for SnortContext

static const char* filter_pegs[] = 
{
    "filtered",
    "inspected",
    "tracked"
};

const char* session_pegs[] =
{
    "sessions",
    "prunes",
    "timeouts",
    "created",
    "released",
    "discards",
    "events"
};

const unsigned session_peg_count = array_size(session_pegs);

//-------------------------------------------------------------------------
// runtime support
//-------------------------------------------------------------------------

static inline bool is_eligible(Packet* p)
{
    if ( p->frag_flag )
        return false;

    if ( p->error_flags & PKT_ERR_CKSUM_IP )
        return false;

    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return false;

    if ( !IPH_IS_VALID(p) )
        return false;

    return true;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Stream5 : public Inspector {
public:
    Stream5(S5Common*);
    ~Stream5();

    void configure(SnortConfig*, const char*, char *args);
    int verify_config(SnortConfig*);
    int verify(SnortConfig*);
    void setup(SnortConfig*);
    void show(SnortConfig*);
    void eval(Packet*);
    bool enabled();
    void init();
    void term();
    void reset();

private:
    Stream5Config* config;
};

Stream5::Stream5 (S5Common* pc)
{
    config = (Stream5Config*)SnortAlloc(sizeof(*config));
    config->common = pc;
    config->handler = this;
}

Stream5::~Stream5()
{
    if ( config->global_config )
        free(config->global_config);

    if ( config->tcp_config )
        Stream5TcpConfigFree(config->tcp_config);

    if ( config->udp_config )
        Stream5UdpConfigFree(config->udp_config);

    if ( config->icmp_config )
        Stream5IcmpConfigFree(config->icmp_config);

    if ( config->ip_config )
        Stream5IpConfigFree(config->ip_config);

    free(config);
}

bool Stream5::enabled ()
{
    return !config->global_config->disabled;
}

void Stream5::configure(
    SnortConfig* sc, const char* key, char* args)
{
    if ( !strcasecmp(key, "stream5_global") )
    {
        Stream5ConfigGlobal(config, sc, args);
    }
    else if ( !strcasecmp(key, "stream5_tcp") )
    {
        if ( config->global_config->track_tcp_sessions )
        {
            if ( !config->tcp_config )
                config->tcp_config = Stream5ConfigTcp(sc, args);
            else
                Stream5ConfigTcp(config->tcp_config, sc, args);
        }
    }
    else if ( !strcasecmp(key, "stream5_udp") )
    {
        if ( config->global_config->track_udp_sessions )
        {
            if ( !config->udp_config )
                config->udp_config = Stream5ConfigUdp(sc, args);
            else
                Stream5ConfigUdp(config->udp_config, args);
        }
    }
    else if ( !strcasecmp(key, "stream5_icmp") )
    {
        if ( config->global_config->track_icmp_sessions && !config->icmp_config )
            config->icmp_config = Stream5ConfigIcmp(sc, args);
    }
    else if ( !strcasecmp(key, "stream5_ip") )
    {
        if ( config->global_config->track_ip_sessions && !config->ip_config )
            config->ip_config = Stream5ConfigIp(sc, args);
    }
#ifdef ENABLE_HA
    else if ( !strcasecmp(key, "stream5_ha") )
    {
        if ( !config->common->ha_config )
            config->common->ha_config = Stream5ConfigHa(sc, args);
    }
#endif

    else
        ParseError("unknown stream5 configuration");
}

int Stream5::verify_config(SnortConfig* sc)
{
    int status = 0;

    if ( config->global_config == NULL )
    {
        WarningMessage("%s(%d) Stream5 global config is NULL.\n",
                __FILE__, __LINE__);
        return -1;
    }

    if ( config->global_config->disabled )
        return 0;

    if (config->global_config->track_tcp_sessions)
    {
        if ( !config->common->max_tcp_sessions ||
             // FIXIT are these checks actually useful?
             // not valid now with thread local flow_con instantiated later
             //!flow_con->max_flows(IPPROTO_TCP) ||
             Stream5VerifyTcpConfig(sc, config->tcp_config) )
        {
            ErrorMessage("WARNING: Stream5 TCP misconfigured.\n");
            status = -1;
        }
    }

    if (config->global_config->track_udp_sessions)
    {
        if ( !config->common->max_udp_sessions || 
             //!flow_con->max_flows(IPPROTO_UDP) ||
             Stream5VerifyUdpConfig(sc, config->udp_config) )
        {
            ErrorMessage("WARNING: Stream5 UDP misconfigured.\n");
            status = -1;
        }
    }

    if (config->global_config->track_icmp_sessions)
    {
        if ( !config->common->max_icmp_sessions || 
             //!flow_con->max_flows(IPPROTO_ICMP) ||
             Stream5VerifyIcmpConfig(sc, config->icmp_config) )
        {
            ErrorMessage("WARNING: Stream5 ICMP misconfigured.\n");
            status = -1;
        }
    }

    if (config->global_config->track_ip_sessions)
    {
        if ( !config->common->max_ip_sessions || 
             //!flow_con->max_flows(IPPROTO_IP) ||
             Stream5VerifyIpConfig(sc, config->ip_config) )
        {
            ErrorMessage("WARNING: Stream5 IP misconfigured.\n");
            status = -1;
        }
    }

    if ( status )
        ErrorMessage("ERROR: Stream5 not properly configured... exiting\n");

    return status;
}

int Stream5::verify(SnortConfig* sc)
{
    int rval;

    if ( (rval = verify_config(sc)) )
        return rval;

#if 0
    // FIXIT no longer valid with thread local flow_con instantiated later
    // also, how is this possible?
    // if just due to failed alloc, then delete
    uint32_t max_tcp = flow_con->max_flows(IPPROTO_TCP);
    uint32_t max_udp = flow_con->max_flows(IPPROTO_UDP);
    uint32_t max_icmp = flow_con->max_flows(IPPROTO_ICMP);
    uint32_t max_ip = flow_con->max_flows(IPPROTO_IP);

    uint32_t total_sessions = max_tcp + max_udp + max_icmp + max_ip;

    if ( !total_sessions )
        return 0;

    if ( (config->common->max_tcp_sessions > 0)
        && (max_tcp == 0) )
    {
        LogMessage("TCP tracking disabled, no TCP sessions allocated\n");
    }

    if ( (config->common->max_udp_sessions > 0)
        && (max_udp == 0) )
    {
        LogMessage("UDP tracking disabled, no UDP sessions allocated\n");
    }

    if ( (config->common->max_icmp_sessions > 0)
        && (max_icmp == 0) )
    {
        LogMessage("ICMP tracking disabled, no ICMP sessions allocated\n");
    }

    if ( (config->common->max_ip_sessions > 0)
        && (max_ip == 0) )
    {
        LogMessage("IP tracking disabled, no IP sessions allocated\n");
    }

    // FIXIT need to get max or set it here for use by init_exp
    //LogMessage("      Max Expected Streams: %u\n", max);
#endif
    return 0;
}

void Stream5::init()
{
    assert(!flow_con);
    flow_con = new FlowControl(config);

    tcp_sinit(config);
}

void Stream5::term()
{
#ifdef ENABLE_HA
    Stream5CleanHA();
#endif

    delete flow_con;
    flow_con = nullptr;

    tcp_sterm();
}

void Stream5::setup(SnortConfig*)
{
#ifdef ENABLE_HA
    if ( config->common->ha_config )
        ha_setup(config->common->ha_config);
#endif
}

void Stream5::show(SnortConfig*)
{
    Stream5PrintGlobalConfig(config);

    if ( config->tcp_config )
        tcp_show(config->tcp_config);

    if ( config->udp_config )
        udp_show(config->udp_config);

    if ( config->icmp_config )
        icmp_show(config->icmp_config);

    if ( config->ip_config )
        ip_show(config->ip_config);

#ifdef ENABLE_HA
    if ( config->common->ha_config )
        ha_show(config->common->ha_config);
#endif
}

void Stream5::eval(Packet *p)
{
    PROFILE_VARS;

    if ( !is_eligible(p) )
        return;

    PREPROC_PROFILE_START(s5PerfStats);

    switch ( GET_IPH_PROTO(p) )
    {
        case IPPROTO_TCP:
            flow_con->process_tcp(config, p);
            break;

        case IPPROTO_UDP:
            flow_con->process_udp(config, p);
            break;

        case IPPROTO_ICMP:
            flow_con->process_icmp(config, p);
            break;

        default:
            flow_con->process_ip(config, p);
            break;
    }

    PREPROC_PROFILE_END(s5PerfStats);
}

void Stream5::reset()
{
    Stream5ResetTcpInstance(config->tcp_config);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static void s5_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        "stream5", &s5PerfStats, 0, &totalPerfStats, s5_get_profile);
#endif

#ifdef ENABLE_HA
    ha_sinit();
#endif
}

// FIXIT move to shared data
static S5Common* s5_hack()
{
    S5Common* pc = (S5Common*)SnortAlloc(sizeof(*pc));

    pc->tcp_mem_cap = S5_DEFAULT_MEMCAP;
    pc->max_tcp_sessions = S5_DEFAULT_MAX_TCP_SESSIONS;
    pc->max_udp_sessions = S5_DEFAULT_MAX_UDP_SESSIONS;
    pc->max_icmp_sessions = S5_DEFAULT_MAX_ICMP_SESSIONS;
    pc->max_ip_sessions = S5_DEFAULT_MAX_IP_SESSIONS;

    pc->tcp_cache_pruning_timeout = S5_DEFAULT_PRUNING_TIMEOUT;
    pc->tcp_cache_nominal_timeout = S5_DEFAULT_NOMINAL_TIMEOUT;

    pc->udp_cache_pruning_timeout = S5_DEFAULT_PRUNING_TIMEOUT;
    pc->udp_cache_nominal_timeout = S5_DEFAULT_NOMINAL_TIMEOUT;

    return pc;
}

#if 0
static void s5_term(void* pv)
{
    S5Common* pc = (S5Common*)pv;

#ifdef ENABLE_HA
    if ( pc->ha_config )
        ha_term(pc->ha_config);
#endif

    free(pc);
}
#endif

static void s5_purge(void*)
{
    flow_con->purge_flows(IPPROTO_TCP);
    flow_con->purge_flows(IPPROTO_UDP);
    flow_con->purge_flows(IPPROTO_ICMP);
    flow_con->purge_flows(IPPROTO_IP);
}

static void s5_stop(void* pv)
{
    s5_purge(pv);
}

static void s5_sum(void*)
{
    sum_stats((PegCount*)&gs5stats.tcp_port_filter,
        (PegCount*)&s5stats.tcp_port_filter, array_size(filter_pegs));

    sum_stats((PegCount*)&gs5stats.udp_port_filter,
        (PegCount*)&s5stats.udp_port_filter, array_size(filter_pegs));

    tcp_sum();
    udp_sum();
    icmp_sum();
    ip_sum();
}

static void s5_stats(void*)
{
    tcp_stats();

    show_stats((PegCount*)&gs5stats.tcp_port_filter, filter_pegs,
        array_size(filter_pegs), "    port filter");

    udp_stats();

    show_stats((PegCount*)&gs5stats.tcp_port_filter, filter_pegs,
        array_size(filter_pegs), "    port filter");

    icmp_stats();
    ip_stats();

#if 0
    // FIXIT add method to get exp cache?
    LogMessage("            Expected Flows\n");
    LogMessage("                  Expected: %lu\n", exp_cache->get_expects());
    LogMessage("                  Realized: %lu\n", exp_cache->get_realized());
    LogMessage("                    Pruned: %lu\n", exp_cache->get_prunes());
    LogMessage("                 Overflows: %lu\n", exp_cache->get_overflows());
#endif
#ifdef ENABLE_HA
    ha_stats();
#endif
}

static void s5_reset(void*)
{
    tcp_reset_stats();
    udp_reset_stats();
    icmp_reset_stats();
    ip_reset_stats();

    // FIXIT reset expected stats

#ifdef ENABLE_HA
    ha_reset_stats();
#endif

    memset(&gs5stats, 0, sizeof(gs5stats));
}

static Inspector* s5_ctor(Module*)
{
    // FIXIT hack until modularized
    S5Common* com = s5_hack();
    return new Stream5(com);
}

static void s5_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi s5_api =
{
    {
        PT_INSPECTOR,
        "stream5",
        INSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    PRIORITY_TRANSPORT,
    // FIXIT protos will be broken up into separate preproc instances
    PROTO_BIT__TCP|PROTO_BIT__UDP|PROTO_BIT__ICMP|PROTO_BIT__IP, // FIXIT based on config
    s5_init,
    nullptr, // term
    s5_ctor,
    s5_dtor,
    s5_stop,
    s5_purge,
    s5_sum,
    s5_stats,
    s5_reset
};

const BaseApi* nin_stream = &s5_api.base;

