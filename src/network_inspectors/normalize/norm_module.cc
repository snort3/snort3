//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "norm_module.h"

#include <string.h>
#include <string>
#include <sstream>
#include <vector>

#include "stream/stream.h"

using namespace std;

static bool allow_names(NormalizerConfig* config, const char* s)
{
    if ( strstr(s, "sack") )
    {
        Norm_TcpPassOption(config, 4);
        Norm_TcpPassOption(config, 5);
    }
    if ( strstr(s, "echo") )
    {
        Norm_TcpPassOption(config, 6);
        Norm_TcpPassOption(config, 7);
    }
    if ( strstr(s, "partial_order") )
    {
        Norm_TcpPassOption(config, 9);
        Norm_TcpPassOption(config, 10);
    }
    if ( strstr(s, "conn_count") )
    {
        Norm_TcpPassOption(config, 11);
        Norm_TcpPassOption(config, 12);
        Norm_TcpPassOption(config, 13);
    }
    if ( strstr(s, "alt_checksum") )
    {
        Norm_TcpPassOption(config, 14);
        Norm_TcpPassOption(config, 15);
    }
    if ( strstr(s, "md5") )
    {
        Norm_TcpPassOption(config, 19);
    }
    return true;
}

static bool allow_codes(NormalizerConfig* config, const char* s)
{
    string str = s;
    stringstream ss(str);

    long opt;

    while ( ss >> opt )
    {
        if ( 2 < opt && opt < 256 )
            Norm_TcpPassOption(config, opt);
        else
            return false;
    }
    return true;
}

//-------------------------------------------------------------------------
// normalize parameters
//-------------------------------------------------------------------------

static const Parameter norm_ip4_params[] =
{
    { "base", Parameter::PT_BOOL, nullptr, "true",
      "clear options" },

    { "df", Parameter::PT_BOOL, nullptr, "false",
      "clear don't frag flag" },

    { "rf", Parameter::PT_BOOL, nullptr, "false",
      "clear reserved flag" },

    { "tos", Parameter::PT_BOOL, nullptr, "false",
      "clear tos / differentiated services byte" },

    { "trim", Parameter::PT_BOOL, nullptr, "false",
      "truncate excess payload beyond datagram length" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter norm_tcp_params[] =
{
    { "base", Parameter::PT_BOOL, nullptr, "true",
      "clear reserved bits and option padding and fix urgent pointer / flags issues" },

    { "ips", Parameter::PT_BOOL, nullptr, "false",
      "ensure consistency in retransmitted data" },

    { "urp", Parameter::PT_BOOL, nullptr, "true",
      "adjust urgent pointer if beyond segment length" },

    { "ecn", Parameter::PT_SELECT, "off | packet | stream", "off",
      "clear ecn for all packets | sessions w/o ecn setup" },

    { "trim", Parameter::PT_BOOL, nullptr, "false",
      "trim data on syn and reset and any outside window or past mss, " },

    { "opts", Parameter::PT_BOOL, nullptr, "false",
      "clear all options except mss, wscale, timestamp, and any explicitly allowed" },

    { "allow_names", Parameter::PT_MULTI, 
      "sack | echo | partial_order | conn_count | alt_checksum | md5", nullptr,
      "don't clear given option names" },

    // FIXIT-L provide a byte list for stuff like this
    { "allow_codes", Parameter::PT_STRING, nullptr, nullptr,
      "don't clear given option codes" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "ip4", Parameter::PT_TABLE, norm_ip4_params, nullptr,
      "set ip4 normalization options" },

    { "tcp", Parameter::PT_TABLE, norm_tcp_params, nullptr,
      "set tcp normalization options" },

    { "ip6", Parameter::PT_BOOL, nullptr, "false",
      "clear reserved flag" },

    { "icmp4", Parameter::PT_BOOL, nullptr, "false",
      "clear reserved flag" },

    { "icmp6", Parameter::PT_BOOL, nullptr, "false",
      "clear reserved flag" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// normalize parameters
//-------------------------------------------------------------------------

NormalizeModule::NormalizeModule() :
    Module(NORM_NAME, NORM_HELP, s_params)
{
    memset(&config, 0, sizeof(config));
}

ProfileStats* NormalizeModule::get_profile() const
{ return &norm_perf_stats; }

bool NormalizeModule::set_ip4(const char*, Value& v, SnortConfig*)
{
    if ( v.is("base") )
        Norm_Set(&config, NORM_IP4_BASE, v.get_bool());

    else if ( v.is("df") )
        Norm_Set(&config, NORM_IP4_DF, v.get_bool());

    else if ( v.is("rf") )
        Norm_Set(&config, NORM_IP4_RF, v.get_bool());

    else if ( v.is("tos") )
        Norm_Set(&config, NORM_IP4_TOS, v.get_bool());

    else if ( v.is("trim") )
        Norm_Set(&config, NORM_IP4_TRIM, v.get_bool());

    else
        return false;

    return true;
}

bool NormalizeModule::set_tcp(const char*, Value& v, SnortConfig*)
{
    if ( v.is("base") )
        Norm_Set(&config, NORM_TCP_BASE, v.get_bool());

    else if ( v.is("urp") )
        Norm_Set(&config, NORM_TCP_URP, v.get_bool());

    else if ( v.is("opts") )
        Norm_Set(&config, NORM_TCP_OPT, v.get_bool());

    else if ( v.is("ips") )
        Norm_Set(&config, NORM_TCP_IPS, v.get_bool());

    else if ( v.is("trim") )
        Norm_Set(&config, NORM_TCP_TRIM, v.get_bool());

    else if ( v.is("ecn") )
    {
        if ( !strcmp(v.get_string(), "packet") )
            Norm_Set(&config, NORM_TCP_ECN_PKT, true);

        else if ( !strcmp(v.get_string(), "stream") )
            Norm_Set(&config, NORM_TCP_ECN_STR, true);
    }
    else if ( v.is("allow_names") )
        return allow_names(&config, v.get_string());

    else if ( v.is("allow_codes") )
        return allow_codes(&config, v.get_string());

    else
        return false;

    return true;
}

bool NormalizeModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    const char* ip4 = NORM_NAME ".ip4";
    const char* tcp = NORM_NAME ".tcp";

    if ( !strncmp(fqn, ip4, strlen(ip4)) )
        return set_ip4(fqn, v, sc);

    else if ( !strncmp(fqn, tcp, strlen(tcp)) )
        return set_tcp(fqn, v, sc);

    else if ( v.is("ip6") )
        Norm_Set(&config, NORM_IP6_BASE, v.get_bool());

    else if ( v.is("icmp4") )
        Norm_Set(&config, NORM_ICMP4, v.get_bool());

    else if ( v.is("icmp6") )
        Norm_Set(&config, NORM_ICMP6, v.get_bool());

    else
        return false;

    return true;
}

bool NormalizeModule::begin(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, "normalizer.ip4") )
        Norm_Set(&config, NORM_IP4_BASE, true);

    else if ( !strcmp(fqn, "normalizer.tcp") )
        Norm_Set(&config, NORM_TCP_BASE, true);

    return true;
}

bool NormalizeModule::end(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, NORM_NAME) )
    {
        NetworkPolicy* policy = get_network_policy();

        if ( (policy->new_ttl > 1) && (policy->new_ttl >= policy->min_ttl) )
        {
            if ( Norm_IsEnabled(&config, NORM_IP4_BASE) )
                Norm_Enable(&config, NORM_IP4_TTL);
        }
        if ( (policy->new_ttl > 1) && (policy->new_ttl >= policy->min_ttl) )
        {
            if ( Norm_IsEnabled(&config, NORM_IP6_BASE) )
                Norm_Enable(&config, NORM_IP6_TTL);
        }
    }
    return true;
}

const PegInfo* NormalizeModule::get_pegs() const
{
    static vector<PegInfo> pegs;
    pegs.clear();

    const PegInfo* p = Norm_GetPegs();
    assert(p);

    while ( p->name )
        pegs.push_back(*p++);

    p = Stream_GetNormPegs();
    assert(p);

    while ( p->name )
        pegs.push_back(*p++);

    pegs.push_back(*p);
    return &pegs[0];
}

PegCount* NormalizeModule::get_counts() const
{
    static vector<PegCount> counts;
    counts.clear();
    unsigned c = 0;

    PegCount* p = Norm_GetCounts(c);

    for ( unsigned i = 0; i < c; ++i )
        counts.push_back(p[i]);

    p = Stream_GetNormCounts(c);

    for ( unsigned i = 0; i < c; ++i )
        counts.push_back(p[i]);

    return &counts[0];
}

