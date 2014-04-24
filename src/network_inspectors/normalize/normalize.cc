/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2010-2013 Sourcefire, Inc.
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

#include "normalize.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "norm.h"
#include "norm_module.h"
#include "packet_io/active.h"
#include "mstring.h"
#include "parser.h"
#include "profiler.h"
#include "snort_types.h"
#include "snort.h"
#include "stream5/stream_tcp.h"
#include "framework/inspector.h"

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats norm_perf_stats;

static PreprocStats* no_get_profile(const char* key)
{
    if ( !strcmp(key, "normalize") )
        return &norm_perf_stats;

    return nullptr;
}
#endif

#define PROTO_BITS (PROTO_BIT__IP|PROTO_BIT__ICMP|PROTO_BIT__TCP)

//-------------------------------------------------------------------------
// printing stuff
//-------------------------------------------------------------------------

#define ON "on"
#define OFF "off"

static inline void LogConf (const char* p, const char* s)
{
    LogMessage("%12s: %s\n", p, s);
}

static inline void LogFlag (
    const char* p, const NormalizerConfig* nc, NormFlags nf)
{
    const char* s = Norm_IsEnabled(nc, nf) ? ON : OFF;
    LogConf(p, s);
}

static void Print_IP4 (SnortConfig*, const NormalizerConfig* nc)
{
    LogFlag("ip4", nc, NORM_IP4);

    if ( Norm_IsEnabled(nc, NORM_IP4) )
    {
        //LogFlag("ip4::id", nc, NORM_IP4_ID);
        LogFlag("ip4::df", nc, NORM_IP4_DF);
        LogFlag("ip4::rf", nc, NORM_IP4_RF);
        LogFlag("ip4::tos", nc, NORM_IP4_TOS);
        LogFlag("ip4::trim", nc, NORM_IP4_TRIM);

        if ( Norm_IsEnabled(nc, NORM_IP4_TTL) )
        {
            NetworkPolicy* policy = get_network_policy();
            LogMessage("%12s: %s (min=%d, new=%d)\n", "ip4::ttl", ON, 
                policy->min_ttl, policy->new_ttl);
        }
        else
            LogConf("ip4::ttl", OFF);
    }
}

static void Print_ICMP4 (const NormalizerConfig* nc)
{
    LogFlag("icmp4", nc, NORM_ICMP4);
}

static void Print_IP6 (SnortConfig*, const NormalizerConfig* nc)
{
    LogFlag("ip6", nc, NORM_IP6);

    if ( Norm_IsEnabled(nc, NORM_IP6) )
    {
        if ( Norm_IsEnabled(nc, NORM_IP6_TTL) )
        {
            NetworkPolicy* policy = get_network_policy();
            LogMessage("%12s: %s (min=%d, new=%d)\n", "ip6::hops",
                ON, policy->min_ttl, policy->new_ttl);
        }
        else
            LogConf("ip6::hops", OFF);
    }
}

static void Print_ICMP6 (const NormalizerConfig* nc)
{
    LogFlag("icmp6", nc, NORM_ICMP6);
}

static void Print_TCP (const NormalizerConfig* nc)
{
    LogFlag("tcp", nc, NORM_TCP);

    if ( Norm_IsEnabled(nc, NORM_TCP) )
    {
        const char* s;

        if ( Norm_IsEnabled(nc, NORM_TCP_ECN_PKT) )
            s = "packet";
        else if ( Norm_IsEnabled(nc, NORM_TCP_ECN_STR) )
            s = "stream";
        else
            s = OFF;

        LogConf("tcp::ecn", s);
        LogFlag("tcp::urp", nc, NORM_TCP_URP);

        if ( Norm_IsEnabled(nc, NORM_TCP_OPT) )
        {
            char buf[1024] = "";
            char* p = buf;
            int opt;
            size_t min;

            p += snprintf(p, buf+sizeof(buf)-p, "%s", "(allow ");
            min = strlen(buf);

            // TBD translate options to keywords allowed by parser
            for ( opt = 2; opt < 256; opt++ )
            {
                const char* fmt = (strlen(buf) > min) ? ",%d" : "%d";
                if ( Norm_TcpIsOptional(nc, opt) )
                    p += snprintf(p, buf+sizeof(buf)-p, fmt, opt);
            }
            if ( strlen(buf) > min )
            {
                snprintf(p, buf+sizeof(buf)-p, "%c", ')');
                buf[sizeof(buf)-1] = '\0';
            }
            LogMessage("%12s: %s %s\n", "tcp::opt", ON, buf);
        }
        else
            LogConf("tcp::opt", OFF);

        LogFlag("tcp::ips", nc, NORM_TCP_IPS);
    }
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Normalizer : public Inspector
{
public:
    Normalizer(NormalizeModule*);

    void configure(SnortConfig*);
    void setup(SnortConfig*);
    void show(SnortConfig*);
    void eval(Packet*);
    bool enabled();

private:
    NormalizerConfig config;
    bool disabled;
};

Normalizer::Normalizer(NormalizeModule* mod)
{
    memcpy(&config, mod->get_config(), sizeof(config));
    disabled = false;
}

bool Normalizer::enabled ()
{
    return !disabled;
}

void Normalizer::configure(SnortConfig*)
{
    // FIXIT detection policy can't be used by normalizer
    // (not set until after normalizer runs)
    if ( get_ips_policy()->policy_mode != POLICY_MODE__INLINE )
    {
        LogMessage("WARNING: normalizations disabled because not inline.\n");
        disabled = true;
        return;
    }

    InspectionPolicy* policy = get_inspection_policy();
    policy->normal_mask = config.normalizer_flags;
}

void Normalizer::setup(SnortConfig*)
{
    NetworkPolicy* policy = get_network_policy();

    if ( policy->new_ttl && policy->new_ttl < policy->min_ttl )
    {
        policy->new_ttl = policy->min_ttl;
    }

    Norm_SetConfig(&config);
}

void Normalizer::show(SnortConfig* sc)
{
    LogMessage("Normalizer config:\n");
    Print_IP4(sc, &config);
    Print_IP6(sc, &config);
    Print_ICMP4(&config);
    Print_ICMP6(&config);
    Print_TCP(&config);
}

void Normalizer::eval(Packet *p)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(norm_perf_stats);

    if ( !Active_PacketWasDropped() )
        Norm_Packet(&config, p);

    PREPROC_PROFILE_END(norm_perf_stats);
    return;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new NormalizeModule; }

static void mod_dtor(Module* m)
{ delete m; }

static const char* name = "normalize";

int Normalize_IsEnabled (SnortConfig*, NormFlags nf)
{
    uint32_t mask = get_inspection_policy()->normal_mask;
    return ( (mask & nf) != 0 );
}

static void no_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        "normalize", &norm_perf_stats, 0, &totalPerfStats, no_get_profile);
#endif
}

static void no_sum(void*)
{
    Norm_SumStats();
    Stream_SumNormalizationStats();
}

static void no_stats(void*)
{
    Norm_PrintStats(name);
    Stream_PrintNormalizationStats();
}

static void no_reset(void*)
{
    Norm_ResetStats();
    Stream_ResetNormalizationStats();
}

static Inspector* no_ctor(Module* m)
{
    return new Normalizer((NormalizeModule*)m);
}

static void no_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi no_api =
{
    {
        PT_INSPECTOR,
        name,
        INSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    PRIORITY_PACKET,
    PROTO_BITS,
    no_init,
    nullptr, // term
    no_ctor,
    no_dtor,
    nullptr, // stop
    nullptr, // purge
    no_sum,
    no_stats,
    no_reset
};

const BaseApi* nin_normalize = &no_api.base;

