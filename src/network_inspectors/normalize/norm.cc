/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

#include "norm.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "perf_monitor/perf.h"
#include "packet_io/sfdaq.h"
#include "protocols/ipv4.h"
#include "protocols/tcp.h"
#include "stream/stream.h"

typedef enum {
    PC_IP4_TRIM,
    PC_IP4_TOS,
    PC_IP4_DF,
    PC_IP4_RF,
    PC_IP4_TTL,
    PC_IP4_OPTS,
    PC_ICMP4_ECHO,
    PC_IP6_TTL,
    PC_IP6_OPTS,
    PC_ICMP6_ECHO,
    PC_TCP_SYN_OPT,
    PC_TCP_TS_ECR,
    PC_TCP_OPT,
    PC_TCP_PAD,
    PC_TCP_RSV,
    PC_TCP_ECN_PKT,
    PC_TCP_NS,
    PC_TCP_URG,
    PC_TCP_URP,
    PC_MAX
} PegCounts;

static const char* pegName[PC_MAX] = {
    "ip4.trim",
    "ip4.tos",
    "ip4.df",
    "ip4.rf",
    "ip4.ttl",
    "ip4.opts",
    "icmp4.echo",
    "ip6.ttl",
    "ip6.opts",
    "icmp6.echo",
    "tcp.syn_opt",
    "tcp.ts_ecr",
    "tcp.opt",
    "tcp.pad",
    "tcp.rsv",
    "tcp.ecn_pkt",
    "tcp.ns",
    "tcp.urg",
    "tcp.urp"
};

static THREAD_LOCAL PegCount normStats[PC_MAX];
static PegCount gnormStats[PC_MAX];

//static int Norm_Eth(Packet*, uint8_t layer, int changes);
static int Norm_IP4(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_ICMP4(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_IP6(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_ICMP6(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_IP6_Opts(NormalizerConfig*, Packet*, uint8_t layer, int changes);
//static int Norm_UDP(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_TCP(NormalizerConfig*, Packet*, uint8_t layer, int changes);

static const uint8_t MAX_EOL_PAD[TCP_OPTLENMAX] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// go from inner to outer
int Norm_Packet (NormalizerConfig* c, Packet* p)
{
    uint8_t lyr = p->num_layers;
    int changes = 0;

    while ( lyr > 0 )
    {
        PROTO_ID proto = p->layers[--lyr].proto;
        NormalFunc n = c->normalizers[proto];
        if ( n ) changes = n(c, p, lyr, changes);
    }

    if ( changes > 0 )
    {
        p->packet_flags |= PKT_MODIFIED;
        return 1;
    }
    if ( p->packet_flags & PKT_RESIZED )
    {
        return 1;
    }
    return 0;
}

//-----------------------------------------------------------------------
// in the following code, we mostly use the actual packet data and the
// packet layers[].  use of other decoded packet members is largely
// avoided to ensure that we don't get tripped up by nested protocols.
// TCP options count and length are a notable exception.
//
// also note that checksums are not calculated here.  they are only
// calculated once after all normalizations are done (here, stream5)
// and any replacements are made.
//-----------------------------------------------------------------------

#if 0
static int Norm_Eth (Packet * p, uint8_t layer, int changes)
{
    return 0;
}
#endif

//-----------------------------------------------------------------------

#define IP4_FLAG_RF 0x8000
#define IP4_FLAG_DF 0x4000
#define IP4_FLAG_MF 0x2000

// TBD support configurable minimum length / obtain from DAQ
// ether header + min payload (excludes FCS, which makes it 64 total)
#define ETH_MIN_LEN 60

static int Norm_IP4 (
    NormalizerConfig* c, Packet * p, uint8_t layer, int changes)
{
    IPHdr* h = (IPHdr*)(p->layers[layer].start);
    uint16_t fragbits = ntohs(h->ip_off);
    uint16_t origbits = fragbits;

    if ( Norm_IsEnabled(c, NORM_IP4_TRIM) && (layer == 1) )
    {
        uint32_t len = p->layers[0].length + ntohs(h->ip_len);

        if ( (len < p->pkth->pktlen) && 
           ( (len >= ETH_MIN_LEN) || (p->pkth->pktlen > ETH_MIN_LEN) )
        ) {
            ((DAQ_PktHdr_t*)p->pkth)->pktlen = (len < ETH_MIN_LEN) ? ETH_MIN_LEN : len;
            p->packet_flags |= PKT_RESIZED;
            normStats[PC_IP4_TRIM]++;
            sfBase.iPegs[PERF_COUNT_IP4_TRIM]++;
        }
    }
    if ( Norm_IsEnabled(c, NORM_IP4_TOS) )
    {
        if ( h->ip_tos )
        {
            h->ip_tos = 0;
            normStats[PC_IP4_TOS]++;
            sfBase.iPegs[PERF_COUNT_IP4_TOS]++;
            changes++;
        }
    }
#if 0
    if ( Norm_IsEnabled(c, NORM_IP4_ID) )
    {
        // TBD implement IP ID normalization / randomization
    }
#endif
    if ( Norm_IsEnabled(c, NORM_IP4_DF) )
    {
        if ( fragbits & IP4_FLAG_DF )
        {
            fragbits &= ~IP4_FLAG_DF;
            normStats[PC_IP4_DF]++;
            sfBase.iPegs[PERF_COUNT_IP4_DF]++;
            changes++;
        }
    }
    if ( Norm_IsEnabled(c, NORM_IP4_RF) )
    {
        if ( fragbits & IP4_FLAG_RF )
        {
            fragbits &= ~IP4_FLAG_RF;
            normStats[PC_IP4_RF]++;
            sfBase.iPegs[PERF_COUNT_IP4_RF]++;
            changes++;
        }
    }
    if ( fragbits != origbits )
    {
        h->ip_off = htons(fragbits);
    }
    if ( Norm_IsEnabled(c, NORM_IP4_TTL) )
    {
        if ( h->ip_ttl < ScMinTTL() )
        {
            h->ip_ttl = ScNewTTL();
            p->error_flags &= ~PKT_ERR_BAD_TTL;
            normStats[PC_IP4_TTL]++;
            sfBase.iPegs[PERF_COUNT_IP4_TTL]++;
            changes++;
        }
    }
    if ( p->layers[layer].length > ip::IP4_HEADER_LEN )
    {
        uint8_t* opts = p->layers[layer].start + ip::IP4_HEADER_LEN;
        uint8_t len = p->layers[layer].length - ip::IP4_HEADER_LEN;
        // expect len > 0 because IHL yields a multiple of 4
        memset(opts, IPOPT_NOP, len);
        normStats[PC_IP4_OPTS]++;
        sfBase.iPegs[PERF_COUNT_IP4_OPTS]++;
        changes++;
    }
    return changes;
}

//-----------------------------------------------------------------------

static int Norm_ICMP4 (
    NormalizerConfig*, Packet* p, uint8_t layer, int changes)
{
    ICMPHdr* h = (ICMPHdr*)(p->layers[layer].start);

    if ( (h->type == ICMP_ECHO || h->type == ICMP_ECHOREPLY) &&
         (h->code != icmp::IcmpCode::ECHO_CODE) )
    {
        h->code =  icmp::IcmpCode::ECHO_CODE;
        normStats[PC_ICMP4_ECHO]++;
        sfBase.iPegs[PERF_COUNT_ICMP4_ECHO]++;
        changes++;
    }
    return changes;
}

//-----------------------------------------------------------------------

static int Norm_IP6 (
    NormalizerConfig* c, Packet * p, uint8_t layer, int changes)
{
    ip::IP6RawHdr* h = (ip::IP6RawHdr*)(p->layers[layer].start);

    if ( Norm_IsEnabled(c, NORM_IP6_TTL) )
    {
        if ( h->ip6_hoplim < ScMinTTL() )
        {
            h->ip6_hoplim = ScNewTTL();
            p->error_flags &= ~PKT_ERR_BAD_TTL;
            normStats[PC_IP6_TTL]++;
            sfBase.iPegs[PERF_COUNT_IP6_TTL]++;
            changes++;
        }
    }
    return changes;
}

//-----------------------------------------------------------------------

static int Norm_ICMP6 (
    NormalizerConfig*, Packet * p, uint8_t layer, int changes)
{
    ICMPHdr* h = (ICMPHdr*)(p->layers[layer].start);

    if ( ((uint16_t)h->type == icmp::Icmp6Types::ECHO_6 ||
          (uint16_t)h->type == icmp::Icmp6Types::REPLY_6) &&
         (h->code != 0) )
    {
        h->code = static_cast<icmp::IcmpCode>(0);
        normStats[PC_ICMP6_ECHO]++;
        sfBase.iPegs[PERF_COUNT_ICMP6_ECHO]++;
        changes++;
    }
    return changes;
}

//-----------------------------------------------------------------------
// we assume here that the decoder has not pushed ip6 option extension
// headers unless the basic sizing is correct (size = N*8 octetes, N>0).

typedef struct
{
    uint8_t next;
    uint8_t xlen;
    uint8_t type;
    uint8_t olen;
} ExtOpt;

#define IP6_OPT_PAD_N 1

static int Norm_IP6_Opts (
    NormalizerConfig*, Packet * p, uint8_t layer, int changes)
{
    uint8_t* b = p->layers[layer].start;
    ExtOpt* x = (ExtOpt*)b;

    // whatever was here, turn it into one PADN option
    x->type = IP6_OPT_PAD_N;
    x->olen = (x->xlen * 8) + 8 - sizeof(*x);
    memset(b+sizeof(*x), 0, x->olen);

    normStats[PC_IP6_OPTS]++;
    sfBase.iPegs[PERF_COUNT_IP6_OPTS]++;
    changes++;

    return changes;
}

//-----------------------------------------------------------------------

#if 0
static int Norm_UDP (Packet * p, uint8_t layer, int changes)
{
    return 0;
}
#endif

//-----------------------------------------------------------------------

static inline void NopDaOpt (uint8_t* opt, uint8_t len)
{
    memset(opt, TCPOPT_NOP, len);
}

#define TS_ECR_OFFSET 6
#define TS_ECR_LENGTH 4

static inline int Norm_TCPOptions (
    NormalizerConfig* config,
    uint8_t* opts, size_t len, const tcp::TCPHdr* h, uint8_t numOpts, int changes)
{
    size_t i = 0;
    uint8_t c = 0;

    while ( (i < len) && (opts[i] != TCPOPT_EOL) &&
        (c++ < numOpts) )
    {
        uint8_t olen = ( opts[i] <= 1 ) ? 1 : opts[i+1];

        // we know that the first numOpts options have valid lengths
        // so we should not need to check individual or total option lengths.
        // however, we keep this as a sanity check.
        if ( i + olen > len)
            break;

        switch ( opts[i] )
        {
        case TCPOPT_NOP:
            break;

        case TCPOPT_MAXSEG:
        case TCPOPT_WSCALE:
            if ( !(h->th_flags & TH_SYN) )
            {
                NopDaOpt(opts+i, olen);
                normStats[PC_TCP_SYN_OPT]++;
                sfBase.iPegs[PERF_COUNT_TCP_SYN_OPT]++;
                changes++;
            }
            break;

        case TCPOPT_TIMESTAMP:
            if ( !(h->th_flags & TH_ACK) &&
                // use memcmp because opts have arbitrary alignment
                memcmp(opts+i+TS_ECR_OFFSET, MAX_EOL_PAD, TS_ECR_LENGTH) )
            {
                // TSecr should be zero unless ACK is set
                memset(opts+i+TS_ECR_OFFSET, 0, TS_ECR_LENGTH);
                normStats[PC_TCP_TS_ECR]++;
                sfBase.iPegs[PERF_COUNT_TCP_TS_ECR]++;
                changes++;
            }
            break;

        default:
            if ( !Norm_TcpIsOptional(config, opts[i]) )
            {
                NopDaOpt(opts+i, olen);
                normStats[PC_TCP_OPT]++;
                sfBase.iPegs[PERF_COUNT_TCP_OPT]++;
                changes++;
            }
        }
        i += olen;
    }
    if ( ++i < len && memcmp(opts+i, MAX_EOL_PAD, len-i) )
    {
        memset(opts+i, 0, len-i);
        normStats[PC_TCP_PAD]++;
        sfBase.iPegs[PERF_COUNT_TCP_PAD]++;
        changes++;
    }
    return changes;
}

static inline int Norm_TCPPadding (
    uint8_t* opts, size_t len, uint8_t numOpts, int changes)
{
    size_t i = 0;
    uint8_t c = 0;

    while ( (i < len) && (opts[i] != TCPOPT_EOL) && (c++ < numOpts) )
    {
        i += ( opts[i] <= 1 ) ? 1 : opts[i+1];
    }
    if ( ++i < len && memcmp(opts+i, MAX_EOL_PAD, len-i) )
    {
        memset(opts+i, 0, len-i);
        normStats[PC_TCP_PAD]++;
        sfBase.iPegs[PERF_COUNT_TCP_PAD]++;
        changes++;
    }
    return changes;
}

static int Norm_TCP (
    NormalizerConfig* c, Packet * p, uint8_t layer, int changes)
{
    tcp::TCPHdr* h = (tcp::TCPHdr*)(p->layers[layer].start);

    if ( h->th_offx2 & TH_RSV )
    {
        h->th_offx2 &= ~TH_RSV;
        normStats[PC_TCP_RSV]++;
        sfBase.iPegs[PERF_COUNT_TCP_RSV]++;
        changes++;
    }
    if ( Norm_IsEnabled(c, NORM_TCP_ECN_PKT) )
    {
        if ( h->th_flags & (TH_CWR|TH_ECE) )
        {
            h->th_flags &= ~(TH_CWR|TH_ECE);
            normStats[PC_TCP_ECN_PKT]++;
            sfBase.iPegs[PERF_COUNT_TCP_ECN_PKT]++;
            changes++;
        }
        if ( h->th_offx2 & TH_NS )
        {
            h->th_offx2 &= ~TH_NS;
            normStats[PC_TCP_NS]++;
            sfBase.iPegs[PERF_COUNT_TCP_NS]++;
            changes++;
        }
    }
    if ( h->th_urp )
    {
        if ( !(h->th_flags & TH_URG) )
        {
            h->th_urp = 0;
            normStats[PC_TCP_URG]++;
            sfBase.iPegs[PERF_COUNT_TCP_URG]++;
            changes++;
        }
        else if ( !p->dsize )
        {
            h->th_flags &= ~TH_URG;
            h->th_urp = 0;
            normStats[PC_TCP_URG]++;
            normStats[PC_TCP_URP]++;
            sfBase.iPegs[PERF_COUNT_TCP_URG]++;
            sfBase.iPegs[PERF_COUNT_TCP_URP]++;
            changes++;
        }
        else if ( Norm_IsEnabled(c, NORM_TCP_URP) &&
            (ntohs(h->th_urp) > p->dsize) )
        {
            h->th_urp = ntohs(p->dsize);
            normStats[PC_TCP_URP]++;
            sfBase.iPegs[PERF_COUNT_TCP_URP]++;
            changes++;
        }
    }
    else if ( h->th_flags & TH_URG )
    {
        h->th_flags &= ~TH_URG;
        normStats[PC_TCP_URG]++;
        sfBase.iPegs[PERF_COUNT_TCP_URG]++;
        changes++;
    }

    uint8_t tcp_options_len = p->tcph->options_len();
    if ( tcp_options_len > 0 )
    {
        uint8_t* opts = p->layers[layer].start + tcp::TCP_HEADER_LEN;

        if ( Norm_IsEnabled(c, NORM_TCP_OPT) )
        {
            changes = Norm_TCPOptions(c, opts, tcp_options_len,
                h, p->tcp_option_count, changes);
        }
        else
        {
            changes = Norm_TCPPadding(opts, tcp_options_len,
                p->tcp_option_count, changes);
        }
    }
    return changes;
}

//-----------------------------------------------------------------------

void Norm_SumStats (void)
{
    sum_stats((PegCount*)&gnormStats, (PegCount*)&normStats, array_size(pegName));
    Stream_SumNormalizationStats();
}

void Norm_PrintStats (const char* name)
{
    show_stats((PegCount*)&gnormStats, pegName, array_size(pegName), name);
    Stream_PrintNormalizationStats();
}

void Norm_ResetStats (void)
{
    memset(gnormStats, 0, sizeof(gnormStats));
    Stream_ResetNormalizationStats();
}

//-----------------------------------------------------------------------

int Norm_SetConfig (NormalizerConfig* nc)
{
    if ( !DAQ_CanReplace() )
    {
        // FIXIT output only once
        //LogMessage("WARNING: normalizations disabled because DAQ"
        //    " can't replace packets.\n");
        nc->normalizer_flags = 0x0;
        return -1;
    }
    if ( !nc->normalizer_flags )
    {
        return 0;
    }
    if ( Norm_IsEnabled(nc, NORM_IP4) )
    {
        nc->normalizers[PROTO_IP4] = Norm_IP4;
    }
    if ( Norm_IsEnabled(nc, NORM_IP4_TRIM) )
    {
        if ( !DAQ_CanInject() )
        {
            LogMessage("WARNING: normalize_ip4: trim disabled since DAQ "
                "can't inject packets.\n");
            Norm_Disable(nc, NORM_IP4_TRIM);
        }
    }
    if ( Norm_IsEnabled(nc, NORM_ICMP4) )
    {
        nc->normalizers[PROTO_ICMP4] = Norm_ICMP4;
    }
    if ( Norm_IsEnabled(nc, NORM_IP6) )
    {
        nc->normalizers[PROTO_IP6] = Norm_IP6;
        nc->normalizers[PROTO_IP6_HOP_OPTS] = Norm_IP6_Opts;
        nc->normalizers[PROTO_IP6_DST_OPTS] = Norm_IP6_Opts;
    }
    if ( Norm_IsEnabled(nc, NORM_ICMP6) )
    {
        nc->normalizers[PROTO_ICMP6] = Norm_ICMP6;
    }
    if ( Norm_IsEnabled(nc, NORM_TCP) )
    {
        nc->normalizers[PROTO_TCP] = Norm_TCP;
    }
    return 0;
}

