//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#include "norm.h"

#include "main/snort_config.h"
#include "packet_io/sfdaq.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/ipv4_options.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"
#include "stream/tcp/tcp_normalizer.h"

using namespace snort;

enum PegCounts
{
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
    PC_TCP_OPT,
    PC_TCP_PAD,
    PC_TCP_RSV,
    PC_TCP_NS,
    PC_TCP_URP,
    PC_TCP_ECN_PKT,
    PC_TCP_TS_ECR,
    PC_TCP_REQ_URG,
    PC_TCP_REQ_PAY,
    PC_TCP_REQ_URP,
    PC_MAX
};

const PegInfo norm_names[] =
{
    { CountType::SUM, "ip4_trim", "eth packets trimmed to datagram size" },
    { CountType::SUM, "ip4_tos", "type of service normalizations" },
    { CountType::SUM, "ip4_df", "don't frag bit normalizations" },
    { CountType::SUM, "ip4_rf", "reserved flag bit clears" },
    { CountType::SUM, "ip4_ttl", "time-to-live normalizations" },
    { CountType::SUM, "ip4_opts", "ip4 options cleared" },
    { CountType::SUM, "icmp4_echo", "icmp4 ping normalizations" },
    { CountType::SUM, "ip6_hops", "ip6 hop limit normalizations" },
    { CountType::SUM, "ip6_options", "ip6 options cleared" },
    { CountType::SUM, "icmp6_echo", "icmp6 echo normalizations" },
    { CountType::SUM, "tcp_syn_options", "SYN only options cleared from non-SYN packets" },
    { CountType::SUM, "tcp_options", "packets with options cleared" },
    { CountType::SUM, "tcp_padding", "packets with padding cleared" },
    { CountType::SUM, "tcp_reserved", "packets with reserved bits cleared" },
    { CountType::SUM, "tcp_nonce", "packets with nonce bit cleared" },
    { CountType::SUM, "tcp_urgent_ptr", "packets without data with urgent pointer cleared" },
    { CountType::SUM, "tcp_ecn_pkt", "packets with ECN bits cleared" },
    { CountType::SUM, "tcp_ts_ecr", "timestamp cleared on non-ACKs" },
    { CountType::SUM, "tcp_req_urg", "cleared urgent pointer when urgent flag is not set" },
    { CountType::SUM, "tcp_req_pay",
        "cleared urgent pointer and urgent flag when there is no payload" },
    { CountType::SUM, "tcp_req_urp", "cleared the urgent flag if the urgent pointer is not set" },
    { CountType::END, nullptr, nullptr }
};

static THREAD_LOCAL PegCount normStats[PC_MAX+PC_TCP_MAX][NORM_MODE_MAX];

//static int Norm_Eth(Packet*, uint8_t layer, int changes);
static int Norm_IP4(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_ICMP4(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_IP6(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_ICMP6(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_IP6_Opts(NormalizerConfig*, Packet*, uint8_t layer, int changes);
//static int Norm_UDP(NormalizerConfig*, Packet*, uint8_t layer, int changes);
static int Norm_TCP(NormalizerConfig*, Packet*, uint8_t layer, int changes);

static const uint8_t MAX_EOL_PAD[TCP_OPTLENMAX] =
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// go from inner to outer
int Norm_Packet(NormalizerConfig* c, Packet* p)
{
    uint8_t lyr = p->num_layers;
    int changes = 0;

    while ( lyr > 0 )
    {
        ProtocolId proto_id = p->layers[--lyr].prot_id;
        NormalFunc n = c->normalizers[PacketManager::proto_idx(proto_id)];

        if ( n )
            changes = n(c, p, lyr, changes);
    }

    if ( changes > 0 )
    {
        p->packet_flags |= PKT_MODIFIED;
        return 1;
    }
    if ( p->packet_flags & (PKT_RESIZED|PKT_MODIFIED) )
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
// calculated once after all normalizations are done (here, stream)
// and any replacements are made.
//-----------------------------------------------------------------------

#if 0
static int Norm_Eth(Packet* p, uint8_t layer, int changes)
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

static inline NormMode get_norm_mode(const Packet * const p)
{
    NormMode mode = NORM_MODE_ON;

    if ( snort::get_inspection_policy()->policy_mode != POLICY_MODE__INLINE )
        mode = NORM_MODE_TEST;

    if ( !SFDAQ::forwarding_packet(p->pkth) )
        mode = NORM_MODE_TEST;

    return mode;
}

static int Norm_IP4(
    NormalizerConfig* c, Packet* p, uint8_t layer, int changes)
{
    ip::IP4Hdr* h = (ip::IP4Hdr*)const_cast<uint8_t*>(p->layers[layer].start);
    uint16_t fragbits = ntohs(h->ip_off);
    uint16_t origbits = fragbits;
    const NormMode mode = get_norm_mode(p);

    if ( Norm_IsEnabled(c, NORM_IP4_TRIM) && (layer == 1) )
    {
        uint32_t len = p->layers[0].length + ntohs(h->ip_len);

        if ( (len < p->pkth->pktlen) &&
            ((len >= ETH_MIN_LEN) || (p->pkth->pktlen > ETH_MIN_LEN)) )
        {
            if ( mode == NORM_MODE_ON )
            {
                (const_cast<DAQ_PktHdr_t*>(p->pkth))->pktlen =
                    (len < ETH_MIN_LEN) ? ETH_MIN_LEN : len;

                p->packet_flags |= PKT_RESIZED;
                changes++;
            }
            normStats[PC_IP4_TRIM][mode]++;
        }
    }
    if ( Norm_IsEnabled(c, NORM_IP4_TOS) )
    {
        if ( h->ip_tos )
        {
            if ( mode == NORM_MODE_ON )
            {
                h->ip_tos = 0;
                changes++;
            }
            normStats[PC_IP4_TOS][mode]++;
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
            if ( mode == NORM_MODE_ON )
            {
                fragbits &= ~IP4_FLAG_DF;
                changes++;
            }
            normStats[PC_IP4_DF][mode]++;
        }
    }
    if ( Norm_IsEnabled(c, NORM_IP4_RF) )
    {
        if ( fragbits & IP4_FLAG_RF )
        {
            if ( mode == NORM_MODE_ON )
            {
                fragbits &= ~IP4_FLAG_RF;
                changes++;
            }
            normStats[PC_IP4_RF][mode]++;
        }
    }
    if ( fragbits != origbits )
    {
        h->ip_off = htons(fragbits);
    }
    if ( Norm_IsEnabled(c, NORM_IP4_TTL) )
    {
        if ( h->ip_ttl < SnortConfig::min_ttl() )
        {
            if ( mode == NORM_MODE_ON )
            {
                h->ip_ttl = SnortConfig::new_ttl();
                p->ptrs.decode_flags &= ~DECODE_ERR_BAD_TTL;
                changes++;
            }
            normStats[PC_IP4_TTL][mode]++;
        }
    }
    if ( p->layers[layer].length > ip::IP4_HEADER_LEN )
    {
        if ( mode == NORM_MODE_ON )
        {
            uint8_t* opts = const_cast<uint8_t*>(p->layers[layer].start) + ip::IP4_HEADER_LEN;
            uint8_t len = p->layers[layer].length - ip::IP4_HEADER_LEN;
            // expect len > 0 because IHL yields a multiple of 4
            memset(opts, static_cast<uint8_t>(ip::IPOptionCodes::NOP), len);
            changes++;
        }
        normStats[PC_IP4_OPTS][mode]++;
    }
    return changes;
}

//-----------------------------------------------------------------------

static int Norm_ICMP4(
    NormalizerConfig*, Packet* p, uint8_t layer, int changes)
{
    ICMPHdr* h = reinterpret_cast<ICMPHdr*>(const_cast<uint8_t*>(p->layers[layer].start));
    const NormMode mode = get_norm_mode(p);

    if ( (h->type == ICMP_ECHO || h->type == ICMP_ECHOREPLY) &&
        (h->code != icmp::IcmpCode::ECHO_CODE) )
    {
        if ( mode == NORM_MODE_ON )
        {
            h->code = icmp::IcmpCode::ECHO_CODE;
            changes++;
        }
        normStats[PC_ICMP4_ECHO][mode]++;
    }
    return changes;
}

//-----------------------------------------------------------------------

static int Norm_IP6(
    NormalizerConfig* c, Packet* p, uint8_t layer, int changes)
{
    if ( Norm_IsEnabled(c, NORM_IP6_TTL) )
    {
        ip::IP6Hdr* h =
            reinterpret_cast<ip::IP6Hdr*>(const_cast<uint8_t*>(p->layers[layer].start));

        if ( h->ip6_hoplim < SnortConfig::min_ttl() )
        {
            const NormMode mode = get_norm_mode(p);

            if ( mode == NORM_MODE_ON )
            {
                h->ip6_hoplim = SnortConfig::new_ttl();
                p->ptrs.decode_flags &= ~DECODE_ERR_BAD_TTL;
                changes++;
            }
            normStats[PC_IP6_TTL][mode]++;
        }
    }
    return changes;
}

//-----------------------------------------------------------------------

static int Norm_ICMP6(
    NormalizerConfig*, Packet* p, uint8_t layer, int changes)
{
    ICMPHdr* h = reinterpret_cast<ICMPHdr*>(const_cast<uint8_t*>(p->layers[layer].start));

    if ( ((uint16_t)h->type == icmp::Icmp6Types::ECHO_REQUEST ||
        (uint16_t)h->type == icmp::Icmp6Types::ECHO_REPLY) &&
        (h->code != 0) )
    {
        const NormMode mode = get_norm_mode(p);

        if ( mode == NORM_MODE_ON )
        {
            h->code = static_cast<icmp::IcmpCode>(0);
            changes++;
        }
        normStats[PC_ICMP6_ECHO][mode]++;
    }
    return changes;
}

//-----------------------------------------------------------------------
// we assume here that the decoder has not pushed ip6 option extension
// headers unless the basic sizing is correct (size = N*8 octets, N>0).

struct ExtOpt
{
    uint8_t next;
    uint8_t xlen;
    uint8_t type;
    uint8_t olen;
};

#define IP6_OPT_PAD_N 1

static int Norm_IP6_Opts(
    NormalizerConfig*, Packet* p, uint8_t layer, int changes)
{
    NormMode mode = get_norm_mode(p);

    if ( mode == NORM_MODE_ON )
    {
        uint8_t* b = const_cast<uint8_t*>(p->layers[layer].start);
        ExtOpt* x = reinterpret_cast<ExtOpt*>(b);

        // whatever was here, turn it into one PADN option
        x->type = IP6_OPT_PAD_N;
        x->olen = (x->xlen * 8) + 8 - sizeof(*x);
        memset(b+sizeof(*x), 0, x->olen);

        changes++;
    }
    normStats[PC_IP6_OPTS][mode]++;
    return changes;
}

//-----------------------------------------------------------------------

#if 0
static int Norm_UDP(Packet* p, uint8_t layer, int changes)
{
    return 0;
}

#endif

//-----------------------------------------------------------------------

static inline void NopDaOpt(uint8_t* opt, uint8_t len)
{
    memset(opt, (uint8_t)tcp::TcpOptCode::NOP, len);
}

#define TS_ECR_OFFSET 6
#define TS_ECR_LENGTH 4

static inline int Norm_TCPOptions(NormalizerConfig* config, const NormMode mode,
    uint8_t* opts, size_t len, const tcp::TCPHdr* h, uint8_t validated_len, int changes)
{
    size_t i = 0;

    while ( (i < len) &&
        (opts[i] != (uint8_t)tcp::TcpOptCode::EOL) &&
        (i < validated_len) )
    {
        uint8_t olen = ( opts[i] <= 1 ) ? 1 : opts[i+1];

        // we know that the first numOpts options have valid lengths
        // so we should not need to check individual or total option lengths.
        // however, we keep this as a sanity check.
        if ( i + olen > len)
            break;

        switch ( static_cast<tcp::TcpOptCode>(opts[i]) )
        {
        case tcp::TcpOptCode::NOP:
            break;

        case tcp::TcpOptCode::MAXSEG:
        case tcp::TcpOptCode::WSCALE:
            if ( !(h->th_flags & TH_SYN) )
            {
                if ( mode == NORM_MODE_ON )
                {
                    NopDaOpt(opts+i, olen);
                    changes++;
                }
                normStats[PC_TCP_SYN_OPT][mode]++;
            }
            break;

        case tcp::TcpOptCode::TIMESTAMP:
            if ( !(h->th_flags & TH_ACK) &&
                // use memcmp because opts have arbitrary alignment
                memcmp(opts+i+TS_ECR_OFFSET, MAX_EOL_PAD, TS_ECR_LENGTH) )
            {
                if ( mode == NORM_MODE_ON )
                {
                    // TSecr should be zero unless ACK is set
                    memset(opts+i+TS_ECR_OFFSET, 0, TS_ECR_LENGTH);
                    changes++;
                }
                normStats[PC_TCP_TS_ECR][mode]++;
            }
            break;

        default:
            if ( !Norm_TcpIsOptional(config, opts[i]) )
            {
                if ( mode == NORM_MODE_ON )
                {
                    NopDaOpt(opts+i, olen);
                    changes++;
                }
                normStats[PC_TCP_OPT][mode]++;
            }
        }
        i += olen;
    }
    if ( ++i < len && memcmp(opts+i, MAX_EOL_PAD, len-i) )
    {
        if ( mode == NORM_MODE_ON )
        {
            memset(opts+i, 0, len-i);
            changes++;
        }
        normStats[PC_TCP_PAD][mode]++;
    }
    return changes;
}

static inline int Norm_TCPPadding(NormalizerConfig*, const NormMode mode,
    uint8_t* opts, size_t len, uint8_t validated_len, int changes)
{
    size_t i = 0;

    while ( (i < len) &&
        (opts[i] != (uint8_t)tcp::TcpOptCode::EOL) &&
        (i < validated_len) )
    {
        i += ( opts[i] <= 1 ) ? 1 : opts[i+1];
    }
    if ( ++i < len && memcmp(opts+i, MAX_EOL_PAD, len-i) )
    {
        if ( mode == NORM_MODE_ON )
        {
            memset(opts+i, 0, len-i);
            changes++;
        }
        normStats[PC_TCP_PAD][mode]++;
    }
    return changes;
}

static int Norm_TCP(
    NormalizerConfig* c, Packet* p, uint8_t layer, int changes)
{
    tcp::TCPHdr* h = reinterpret_cast<tcp::TCPHdr*>(const_cast<uint8_t*>(p->layers[layer].start));
    const NormMode mode = get_norm_mode(p);

    if ( Norm_IsEnabled(c, NORM_TCP_RSV) )
    {
        if ( h->th_offx2 & TH_RSV )
        {
            if ( mode == NORM_MODE_ON )
            {
                h->th_offx2 &= ~TH_RSV;
                changes++;
            }
            normStats[PC_TCP_RSV][mode]++;
        }
    }
    if ( Norm_IsEnabled(c, NORM_TCP_ECN_PKT) )
    {
        if ( h->th_flags & (TH_CWR|TH_ECE) )
        {
            if ( mode == NORM_MODE_ON )
            {
                h->th_flags &= ~(TH_CWR|TH_ECE);
                changes++;
            }
            normStats[PC_TCP_ECN_PKT][mode]++;
        }
        if ( h->th_offx2 & TH_NS )
        {
            if ( mode == NORM_MODE_ON )
            {
                h->th_offx2 &= ~TH_NS;
                changes++;
            }
            normStats[PC_TCP_NS][mode]++;
        }
    }
    if ( h->th_urp )
    {
        if ( !(h->th_flags & TH_URG) )
        {
            if ( Norm_IsEnabled(c, NORM_TCP_REQ_URG) )
            {
                if ( mode == NORM_MODE_ON )
                {
                    h->th_urp = 0;
                    changes++;
                }
                normStats[PC_TCP_REQ_URG][mode]++;
            }
        }
        else if ( !p->dsize )
        {
            if ( Norm_IsEnabled(c, NORM_TCP_REQ_PAY) )
            {
                if ( mode == NORM_MODE_ON )
                {
                    h->th_flags &= ~TH_URG;
                    h->th_urp = 0;
                    changes++;
                }
                normStats[PC_TCP_REQ_PAY][mode]++;
            }
        }
        else if ( h->urp() > p->dsize )
        {
            if ( Norm_IsEnabled(c, NORM_TCP_URP) )
            {
                if ( mode == NORM_MODE_ON )
                {
                    h->set_urp(p->dsize);
                    changes++;
                }
                normStats[PC_TCP_URP][mode]++;
            }
        }
    }
    else if ( Norm_IsEnabled(c, NORM_TCP_REQ_URP) )
    {
        if ( h->th_flags & TH_URG )
        {
            if ( mode == NORM_MODE_ON )
            {
                h->th_flags &= ~TH_URG;
                changes++;
            }
            normStats[PC_TCP_REQ_URP][mode]++;
        }
    }

    uint8_t tcp_options_len = h->options_len();

    if ( tcp_options_len > 0 )
    {
        const Layer& lyr = p->layers[layer];
        uint8_t* opts = const_cast<uint8_t*>(lyr.start) + tcp::TCP_MIN_HEADER_LEN;
        // lyr.length only includes valid tcp options
        uint8_t valid_opts_len = lyr.length - tcp::TCP_MIN_HEADER_LEN;

        if ( Norm_IsEnabled(c, NORM_TCP_OPT) )
        {
            changes = Norm_TCPOptions(c, mode, opts,
                tcp_options_len, h, valid_opts_len, changes);
        }
        else if ( Norm_IsEnabled(c, NORM_TCP_PAD) )
        {
            changes = Norm_TCPPadding(c, mode, opts,
                tcp_options_len, valid_opts_len, changes);
        }
    }
    return changes;
}

//-----------------------------------------------------------------------

const PegInfo* Norm_GetPegs()
{ return norm_names; }

NormPegs Norm_GetCounts(unsigned& c)
{
    c = PC_MAX;
    return normStats;
}

//-----------------------------------------------------------------------

int Norm_SetConfig(NormalizerConfig* nc)
{
    if ( !nc->normalizer_flags )
    {
        return 0;
    }
    if ( Norm_IsEnabled(nc, (NormFlags)NORM_IP4_ANY) )
    {
        nc->normalizers[PacketManager::proto_idx(ProtocolId::ETHERTYPE_IPV4)] = Norm_IP4;
    }
    if ( Norm_IsEnabled(nc, NORM_ICMP4) )
    {
        nc->normalizers[PacketManager::proto_idx(ProtocolId::ICMPV4)] = Norm_ICMP4;
    }
    if ( Norm_IsEnabled(nc, (NormFlags)NORM_IP6_ANY) )
    {
        nc->normalizers[PacketManager::proto_idx(ProtocolId::IPV6)] = Norm_IP6;
        nc->normalizers[PacketManager::proto_idx(ProtocolId::HOPOPTS)] = Norm_IP6_Opts;
        nc->normalizers[PacketManager::proto_idx(ProtocolId::DSTOPTS)] = Norm_IP6_Opts;
    }
    if ( Norm_IsEnabled(nc, NORM_ICMP6) )
    {
        nc->normalizers[PacketManager::proto_idx(ProtocolId::ICMPV6)] = Norm_ICMP6;
    }
    if ( Norm_IsEnabled(nc, (NormFlags)NORM_TCP_ANY) )
    {
        nc->normalizers[PacketManager::proto_idx(ProtocolId::TCP)] = Norm_TCP;
    }
    return 0;
}

