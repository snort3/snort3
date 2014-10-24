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

#include "norm.h"
#include "norm_module.h"
#include "packet_io/active.h"
#include "mstring.h"
#include "parser.h"
#include "profiler.h"
#include "snort_types.h"
#include "snort.h"
#include "framework/inspector.h"

THREAD_LOCAL ProfileStats norm_perf_stats;

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
    Normalizer(const NormalizerConfig&);

    void tinit() override;
    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    NormalizerConfig config;
    bool disabled;
};

Normalizer::Normalizer(const NormalizerConfig& nc)
{
    config = nc;
    disabled = false;
}

void Normalizer::tinit()
{
    // FIXIT-H this isn't good with -z > 1
    // this ensures we init just once but there is a race cond
    // with other threads that won't normalize until this is done
    if ( get_instance_id() ) 
        return;

    if ( get_ips_policy()->policy_mode != POLICY_MODE__INLINE )
    {
        ParseWarning("normalizations disabled because not inline.\n");
        disabled = true;
        return;
    }

    NetworkPolicy* nap = get_network_policy();

    if ( nap->new_ttl && nap->new_ttl < nap->min_ttl )
    {
        nap->new_ttl = nap->min_ttl;
    }

    Norm_SetConfig(&config);
    return;
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
    MODULE_PROFILE_START(norm_perf_stats);

    if ( !PacketIsRebuilt(p) && !Active_PacketWasDropped() )
        Norm_Packet(&config, p);

    MODULE_PROFILE_END(norm_perf_stats);
    return;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new NormalizeModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* no_ctor(Module* m)
{
    NormalizeModule* mod = (NormalizeModule*)m;
    return new Normalizer(*mod->get_config());
}

static void no_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi no_api =
{
    {
        PT_INSPECTOR,
        NORM_NAME,
        NORM_HELP,
        INSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    IT_PACKET,
    (uint16_t)PktType::ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    no_ctor,
    no_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* nin_normalize = &no_api.base;

