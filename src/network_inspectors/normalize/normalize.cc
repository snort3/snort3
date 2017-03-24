//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "normalize.h"

#include "log/messages.h"
#include "main/policy.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "profiler/profiler.h"

#include "norm_module.h"

THREAD_LOCAL ProfileStats norm_perf_stats;
static THREAD_LOCAL uint32_t t_flags = 0;

//-------------------------------------------------------------------------
// printing stuff
//-------------------------------------------------------------------------

#define ON "on"
#define OFF "off"

static inline void LogConf(const char* p, const char* s)
{
    LogMessage("%12s: %s\n", p, s);
}

static inline void LogFlag(
    const char* p, const NormalizerConfig* nc, NormFlags nf)
{
    const char* s = Norm_IsEnabled(nc, nf) ? ON : OFF;
    LogConf(p, s);
}

static void Print_IP4(SnortConfig*, const NormalizerConfig* nc)
{
    if ( !Norm_IsEnabled(nc, (NormFlags)NORM_IP4_ANY) )
        return;

    LogFlag("ip4.base", nc, NORM_IP4_BASE);
    //LogFlag("ip4.id", nc, NORM_IP4_ID);
    LogFlag("ip4.df", nc, NORM_IP4_DF);
    LogFlag("ip4.rf", nc, NORM_IP4_RF);
    LogFlag("ip4.tos", nc, NORM_IP4_TOS);
    LogFlag("ip4.trim", nc, NORM_IP4_TRIM);

    if ( Norm_IsEnabled(nc, NORM_IP4_TTL) )
    {
        NetworkPolicy* policy = get_network_policy();
        LogMessage("%12s: %s (min=%d, new=%d)\n", "ip4.ttl", ON,
            policy->min_ttl, policy->new_ttl);
    }
    else
        LogConf("ip4.ttl", OFF);
}

static void Print_ICMP4(const NormalizerConfig* nc)
{
    LogFlag("icmp4", nc, NORM_ICMP4);
}

static void Print_IP6(SnortConfig*, const NormalizerConfig* nc)
{
    if ( !Norm_IsEnabled(nc, (NormFlags)NORM_IP6_ANY) )
        return;

    LogFlag("ip6.base", nc, NORM_IP6_BASE);

    if ( Norm_IsEnabled(nc, NORM_IP6_TTL) )
    {
        NetworkPolicy* policy = get_network_policy();
        LogMessage("%12s: %s (min=%d, new=%d)\n", "ip6.hops",
            ON, policy->min_ttl, policy->new_ttl);
    }
}

static void Print_ICMP6(const NormalizerConfig* nc)
{
    LogFlag("icmp6", nc, NORM_ICMP6);
}

static void Print_TCP(const NormalizerConfig* nc)
{
    if ( !Norm_IsEnabled(nc, (NormFlags)NORM_TCP_ANY) )
        return;

    const char* s;

    if ( Norm_IsEnabled(nc, NORM_TCP_ECN_PKT) )
        s = "packet";
    else if ( Norm_IsEnabled(nc, NORM_TCP_ECN_STR) )
        s = "stream";
    else
        s = OFF;

    LogConf("tcp.ecn", s);
    LogFlag("tcp.block", nc, NORM_TCP_BLOCK);
    LogFlag("tcp.rsv", nc, NORM_TCP_RSV);
    LogFlag("tcp.pad", nc, NORM_TCP_PAD);
    LogFlag("tcp.req_urg", nc, NORM_TCP_REQ_URG);
    LogFlag("tcp.req_pay", nc, NORM_TCP_REQ_PAY);
    LogFlag("tcp.req_urp", nc, NORM_TCP_REQ_URP);
    LogFlag("tcp.urp", nc, NORM_TCP_URP);

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
        LogMessage("%12s: %s %s\n", "tcp.opt", ON, buf);
    }
    else
        LogConf("tcp.opt", OFF);

    LogFlag("tcp.ips", nc, NORM_TCP_IPS);
    LogFlag("tcp.trim_syn", nc, NORM_TCP_TRIM_SYN);
    LogFlag("tcp.trim_rst", nc, NORM_TCP_TRIM_RST);
    LogFlag("tcp.trim_win", nc, NORM_TCP_TRIM_WIN);
    LogFlag("tcp.trim_mss", nc, NORM_TCP_TRIM_MSS);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Normalizer : public Inspector
{
public:
    Normalizer(const NormalizerConfig&);

    bool configure(SnortConfig*) override;
    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    NormalizerConfig config;
};

Normalizer::Normalizer(const NormalizerConfig& nc)
{
    config = nc;
}

// FIXIT-L this works with one normalizer per policy
// but would be better if binder could select
// in which case normal_mask must be moved to flow
bool Normalizer::configure(SnortConfig*)
{
    PolicyMode mode = get_ips_policy()->policy_mode;
    // FIXIT-L norm needs a nap policy mode
    if ( mode == POLICY_MODE__PASSIVE )
    {
        ParseWarning(WARN_DAQ, "normalizations disabled because not inline.");
        config.normalizer_flags = 0;
        return true;
    }

    NetworkPolicy* nap = get_network_policy();
    nap->normal_mask = config.normalizer_flags;

    if ( nap->new_ttl && nap->new_ttl < nap->min_ttl )
    {
        nap->new_ttl = nap->min_ttl;
    }

    config.norm_mode = (mode == POLICY_MODE__INLINE) ? NORM_MODE_ON : NORM_MODE_TEST;
    Norm_SetConfig(&config);
    return true;
}

// FIXIT-L norm flags check should be moved to flow
// set flow flags once at start of flow
bool Normalize_IsEnabled(NormFlags nf)
{
    if ( !(t_flags & nf) )
        return false;

    NetworkPolicy* nap = get_network_policy();
    return ( (nap->normal_mask & nf) != 0 );
}

NormMode Normalize_GetMode(NormFlags nf)
{
    if (Normalize_IsEnabled(nf))
    {
        const PolicyMode mode = get_ips_policy()->policy_mode;

        if ( mode == POLICY_MODE__INLINE )
            return NORM_MODE_ON;

        else if ( mode == POLICY_MODE__INLINE_TEST )
            return NORM_MODE_TEST;
    }
    return NORM_MODE_TEST;
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

void Normalizer::eval(Packet* p)
{
    Profile profile(norm_perf_stats);

    if ( !p->is_rebuilt() && !Active::packet_was_dropped() )
        Norm_Packet(&config, p);
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

static void no_tinit()
{
    if ( SFDAQ::can_replace() )
        t_flags = NORM_ALL;

    if ( !SFDAQ::can_inject() )
        t_flags &= ~NORM_IP4_TRIM;
}

static const InspectApi no_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        NORM_NAME,
        NORM_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PACKET,
    (uint16_t)PktType::ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    no_tinit,
    nullptr, // tterm
    no_ctor,
    no_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* nin_normalize = &no_api.base;

