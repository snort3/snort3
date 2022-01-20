//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "utils/util_cstring.h"

#include "norm_module.h"

using namespace snort;

THREAD_LOCAL ProfileStats norm_perf_stats;
static THREAD_LOCAL uint32_t t_flags = 0;

//-------------------------------------------------------------------------
// printing stuff
//-------------------------------------------------------------------------
static inline std::string to_str(bool flag)
{
    return flag ? "enabled" : "disabled";
}

static void print_ip4(const NormalizerConfig* nc)
{
    bool ip4 = Norm_IsEnabled(nc, (NormFlags)NORM_IP4_ANY);
    ConfigLogger::log_flag("ip4", ip4);

    if ( !ip4 )
        return;

    std::string opts;
    opts += "{ base = " + to_str(Norm_IsEnabled(nc, NORM_IP4_BASE));
    opts += ", df = " + to_str(Norm_IsEnabled(nc, NORM_IP4_DF));
    opts += ", rf = " + to_str(Norm_IsEnabled(nc,  NORM_IP4_RF));
    opts += ", tos = " + to_str(Norm_IsEnabled(nc, NORM_IP4_TOS));
    opts += ", trim = " + to_str(Norm_IsEnabled(nc, NORM_IP4_TRIM));
    opts += ", ttl = " + to_str(Norm_IsEnabled(nc, NORM_IP4_TTL));

    if ( Norm_IsEnabled(nc, NORM_IP4_TTL) )
    {
        NetworkPolicy* policy = get_network_policy();
        opts += ", min_ttl = " + std::to_string(policy->min_ttl);
        opts += ", new_ttl = " + std::to_string(policy->new_ttl);
    }

    opts += " }";

    ConfigLogger::log_list("ip4", opts.c_str());
}

static void print_icmp4(const NormalizerConfig* nc)
{
    ConfigLogger::log_flag("icmp4", Norm_IsEnabled(nc, NORM_ICMP4));
}

static void print_ip6(const NormalizerConfig* nc)
{
    bool ip6 = Norm_IsEnabled(nc, (NormFlags)NORM_IP6_ANY);
    ConfigLogger::log_flag("ip6", ip6);

    if ( !ip6 )
        return;

    std::string opts;
    opts += "{ base = " + to_str(Norm_IsEnabled(nc, NORM_IP6_BASE));

    if ( Norm_IsEnabled(nc, NORM_IP6_TTL) )
    {
        NetworkPolicy* policy = get_network_policy();
        opts += ", min_ttl = " + std::to_string(policy->min_ttl);
        opts += ", new_ttl = " + std::to_string(policy->new_ttl);
    }

    opts += " }";

    ConfigLogger::log_list("ip6", opts.c_str());
}

static void print_icmp6(const NormalizerConfig* nc)
{
    ConfigLogger::log_flag("icmp6", Norm_IsEnabled(nc, NORM_ICMP6));
}

static std::string get_allowed_names(const NormalizerConfig* config)
{
    std::string names;
    if ( Norm_TcpIsOptional(config, 4) or Norm_TcpIsOptional(config, 5) )
        names += "sack";

    if ( Norm_TcpIsOptional(config, 6) or Norm_TcpIsOptional(config, 7) )
        names += " echo";

    if ( Norm_TcpIsOptional(config, 9) or Norm_TcpIsOptional(config, 10) )
        names += " partial_order";

    if ( Norm_TcpIsOptional(config, 11) or Norm_TcpIsOptional(config, 12)
        or Norm_TcpIsOptional(config, 13) )
        names += " conn_count";

    if ( Norm_TcpIsOptional(config, 14) or Norm_TcpIsOptional(config, 15) )
        names += " alt_checksum";

    if ( Norm_TcpIsOptional(config, 19) )
        names += " md5";

    return names;
}

static std::string get_allowed_codes(const NormalizerConfig* nc)
{
    std::string codes;
    std::unordered_set<int> named_codes = {4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 19};

    for (int opt = 2; opt < 256; opt++)
    {
        if ( Norm_TcpIsOptional(nc, opt) and !named_codes.count(opt) )
            codes += std::to_string(opt) + ", ";
    }

    if ( !codes.empty() )
        codes.erase(codes.end() - 2);

    return codes;
}

static void print_tcp(const NormalizerConfig* nc)
{
    bool tcp = Norm_IsEnabled(nc, (NormFlags)NORM_TCP_ANY);
    ConfigLogger::log_flag("tcp", tcp);

    if ( !tcp )
        return;

    std::string opts;

    opts += "{ ecn = ";
    if ( Norm_IsEnabled(nc, NORM_TCP_ECN_PKT) )
        opts += "packet";
    else if ( Norm_IsEnabled(nc, NORM_TCP_ECN_STR) )
        opts +="stream";
    else
        opts += to_str(false);

    opts += ", block = " + to_str(Norm_IsEnabled(nc, NORM_TCP_BLOCK));
    opts += ", rsv = " + to_str(Norm_IsEnabled(nc, NORM_TCP_RSV));
    opts += ", pad = " + to_str(Norm_IsEnabled(nc, NORM_TCP_PAD));
    opts += ", req_urg = " + to_str(Norm_IsEnabled(nc, NORM_TCP_REQ_URG));
    opts += ", req_pay = " + to_str(Norm_IsEnabled(nc, NORM_TCP_REQ_PAY));
    opts += ", req_urp = " + to_str(Norm_IsEnabled(nc, NORM_TCP_REQ_URP));
    opts += ", urp = " + to_str(Norm_IsEnabled(nc, NORM_TCP_URP));
    opts += ", ips = " + to_str(Norm_IsEnabled(nc, NORM_TCP_IPS));

    auto names = get_allowed_names(nc);
    auto codes = get_allowed_codes(nc);

    if ( !names.empty() )
        opts += ", allow_names = { " + names + " }";

    if ( !codes.empty() )
        opts += ", allow_codes = { " + codes + " }";

    if ( Norm_IsEnabled(nc, (NormFlags)NORM_TCP_TRIM_ANY) )
    {
        opts += ", trim_syn = " + to_str(Norm_IsEnabled(nc, NORM_TCP_TRIM_SYN));
        opts += ", trim_rst = " + to_str(Norm_IsEnabled(nc, NORM_TCP_TRIM_RST));
        opts += ", trim_win = " + to_str(Norm_IsEnabled(nc, NORM_TCP_TRIM_WIN));
        opts += ", trim_mss = " + to_str(Norm_IsEnabled(nc, NORM_TCP_TRIM_MSS));
    }
    else
        opts += ", trim = " + to_str(false);

    opts += " }";

    ConfigLogger::log_list("tcp", opts.c_str());
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Normalizer : public Inspector
{
public:
    Normalizer(const NormalizerConfig&);

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;
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
// from cwaxman - why can't normal_mask be applied directly from Normalizer?
bool Normalizer::configure(SnortConfig*)
{
    // FIXIT-M move entire config to network policy? Leaving split loads the currently selected
    // network policy with whichever instantiation of an inspection policy this normalize is in
    NetworkPolicy* nap = get_network_policy();

    if ( nap->new_ttl && nap->new_ttl < nap->min_ttl )
        nap->new_ttl = nap->min_ttl;

    if ( (nap->new_ttl > 1) && (nap->new_ttl >= nap->min_ttl) )
    {
        if ( Norm_IsEnabled(&config, NORM_IP4_BASE) )
            Norm_Enable(&config, NORM_IP4_TTL);

        if ( Norm_IsEnabled(&config, NORM_IP6_BASE) )
            Norm_Enable(&config, NORM_IP6_TTL);
    }

    nap->normal_mask = config.normalizer_flags;

    Norm_SetConfig(&config);
    return true;
}

// FIXIT-L norm flags check should be moved to flow
// set flow flags once at start of flow
bool Normalize_IsEnabled(NormFlags nf)
{
    if ( !(t_flags & nf) )
        return false;

    if ( get_inspection_policy()->policy_mode != POLICY_MODE__INLINE )
        return false;

    NetworkPolicy* nap = get_network_policy();
    return nap->normal_mask & nf;
}

NormMode Normalize_GetMode(NormFlags nf)
{
    if (Normalize_IsEnabled(nf))
    {
        const PolicyMode mode = get_inspection_policy()->policy_mode;

        if ( mode == POLICY_MODE__INLINE )
            return NORM_MODE_ON;
    }
    return NORM_MODE_TEST;
}

void Normalizer::show(const SnortConfig*) const
{
    print_ip4(&config);
    print_ip6(&config);
    print_icmp4(&config);
    print_icmp6(&config);
    print_tcp(&config);
}

void Normalizer::eval(Packet* p)
{
    Profile profile(norm_perf_stats);

    if ( !p->is_rebuilt() && !p->active->packet_was_dropped() )
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
    PROTO_BIT__ANY_IP,
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

