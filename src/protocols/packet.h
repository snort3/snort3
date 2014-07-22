/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef PACKET_H
#define PACKET_H

/*  I N C L U D E S  **********************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#else /* !WIN32 */
#include <netinet/in_systm.h>
#ifndef IFNAMSIZ
#define IFNAMESIZ MAX_ADAPTER_NAME
#endif /* !IFNAMSIZ */
#endif /* !WIN32 */

extern "C" {
#include <daq.h>
#include <sfbpf_dlt.h>
}

#include "main/snort_types.h"
#include "sfip/ipv6_port.h"
#include "sfip/sf_ip.h"
#include "sfip/sf_iph.h"
#include "codecs/sf_protocols.h"


#include "protocols/layer.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/mpls.h"

/*  D E F I N E S  ************************************************************/

/* packet status flags */
#define PKT_REBUILT_FRAG     0x00000001  /* is a rebuilt fragment */
#define PKT_REBUILT_STREAM   0x00000002  /* is a rebuilt stream */
#define PKT_STREAM_UNEST_UNI 0x00000004  /* is from an unestablished stream and
                                          * we've only seen traffic in one direction */
#define PKT_STREAM_EST       0x00000008  /* is from an established stream */

#define PKT_STREAM_INSERT    0x00000010  /* this packet has been queued for stream reassembly */
#define PKT_STREAM_TWH       0x00000020  /* packet completes the 3-way handshake */
#define PKT_FROM_SERVER      0x00000040  /* this packet came from the server
                                            side of a connection (TCP) */
#define PKT_FROM_CLIENT      0x00000080  /* this packet came from the client
                                            side of a connection (TCP) */

#define PKT_PDU_HEAD         0x00000100  /* start of PDU */
#define PKT_PDU_TAIL         0x00000200  /* end of PDU */
#define PKT_UNSURE_ENCAP     0x00000400  /* packet may have incorrect encapsulation layer. */
                                         /* don't alert if "next layer" is invalid. */
#define PKT_HTTP_DECODE      0x00000800  /* this packet has normalized http */

#define PKT_IGNORE           0x00001000  /* this packet should be ignored, based on port */
#define PKT_TRUST            0x00002000  /* this packet should fallback to being whitelisted if no other verdict was specified */
#define PKT_ALLOW_MULTIPLE_DETECT 0x00004000  /* packet has either pipelined mime attachements */
                                              /* or pipeline http requests */
#define PKT_PAYLOAD_OBFUSCATE     0x00008000

#define PKT_STATELESS        0x00010000  /* Packet has matched a stateless rule */
#define PKT_PASS_RULE        0x00020000  /* this packet has matched a pass rule */
#define PKT_IP_RULE          0x00040000  /* this packet is being evaluated against an IP rule */
#define PKT_IP_RULE_2ND      0x00080000  /* this packet is being evaluated against an IP rule */

#define PKT_PSEUDO           0x00100000  /* is a pseudo packet */
#define PKT_MODIFIED         0x00200000  /* packet had normalizations, etc. */
#define PKT_RESIZED          0x00300000  /* packet has new size; must set modified too */

// neither of these flags will be set for (full) retransmissions or non-data segments
// a partial overlap results in out of sequence condition
// out of sequence condition is sticky
#define PKT_STREAM_ORDER_OK  0x00800000  /* this segment is in order, w/o gaps */
#define PKT_STREAM_ORDER_BAD 0x01000000  /* this stream had at least one gap */
#define PKT_REASSEMBLED_OLD  0x02000000  /* for backwards compat with so rules */

#define PKT_FILE_EVENT_SET   0x04000000
#define PKT_ESP_LYR_PRESENT  0x08000000

// 0x40000000 are available
#define PKT_PDU_FULL (PKT_PDU_HEAD | PKT_PDU_TAIL)

#define REASSEMBLED_PACKET_FLAGS (PKT_REBUILT_STREAM|PKT_REASSEMBLED_OLD)

enum PseudoPacketType{
    PSEUDO_PKT_IP,
    PSEUDO_PKT_TCP,
    PSEUDO_PKT_DCE_RPKT,
    PSEUDO_PKT_SMB_SEG,
    PSEUDO_PKT_DCE_SEG,
    PSEUDO_PKT_DCE_FRAG,
    PSEUDO_PKT_SMB_TRANS,
    PSEUDO_PKT_PS,
    PSEUDO_PKT_SDF,
    PSEUDO_PKT_MAX
} ;

/* error flags */
#define PKT_ERR_CKSUM_IP     0x01
#define PKT_ERR_CKSUM_TCP    0x02
#define PKT_ERR_CKSUM_UDP    0x04
#define PKT_ERR_CKSUM_ICMP   0x08
#define PKT_ERR_CKSUM_ANY    0x0F
#define PKT_ERR_BAD_TTL      0x10


/* We must twiddle to align the offset the ethernet header and align
 * the IP header on solaris -- maybe this will work on HPUX too.
 */
#if defined (SOLARIS) || defined (SUNOS) || defined (__sparc__) || defined(__sparc64__) || defined (HPUX)
#define SPARC_TWIDDLE       2
#else
#define SPARC_TWIDDLE       0
#endif


/* default mpls flags */
#define DEFAULT_MPLS_PAYLOADTYPE      MPLS_PAYLOADTYPE_IPV4
#define DEFAULT_LABELCHAIN_LENGTH    -1

const int32_t MAX_PORTS = 65536;
const uint16_t NUM_IP_PROTOS = 256;
const int16_t SFTARGET_UNKNOWN_PROTOCOL = -1;
const uint8_t IP_OPTMAX = 40;
const uint8_t TCP_OPTLENMAX = 40; /* (((2^4) - 1) * 4  - TCP_HEADER_LEN) */
const uint8_t IP6_EXTMAX = 8;
const uint8_t MIN_TTL = 64;
const uint8_t MAX_TTL = 255;



/*  D A T A  S T R U C T U R E S  *********************************************/
class Flow;


struct Options
{
    uint8_t code;
    uint8_t len; /* length of the data section */
    const uint8_t *data;
} ;


const uint8_t LAYER_MAX = 32;

struct Packet
{
    const DAQ_PktHdr_t *pkth;    // packet meta data
    const uint8_t *pkt;         // raw packet data

    //vvv------------------------------------------------
    // TODO convenience stuff to be refactored for layers
    //^^^------------------------------------------------

    //vvv-----------------------------

    const IPHdr *iph, *orig_iph;/* and orig. headers for ICMP_*_UNREACH family */
    const IPHdr *inner_iph;     /* if IP-in-IP, this will be the inner IP header */
    const IPHdr *outer_iph;     /* if IP-in-IP, this will be the outer IP header */
    const TCPHdr *tcph, *orig_tcph;
    const udp::UDPHdr *udph, *orig_udph;
    const udp::UDPHdr *outer_udph;   /* if Teredo + UDP, this will be the outer UDP header */
    const ICMPHdr *icmph, *orig_icmph;

    const uint8_t *data;        /* packet payload pointer */
    const uint8_t *ip_data;     /* IP payload pointer */
    const uint8_t *outer_ip_data;  /* Outer IP payload pointer */
    //^^^-----------------------------

    Flow* flow;   /* for session tracking */

    //vvv-----------------------------
    ipv4::IP4Hdr *ip4h, *orig_ip4h;
    ipv6::IP6Hdr *ip6h, *orig_ip6h;
    icmp6::ICMP6Hdr *icmp6h, *orig_icmp6h;

    IPH_API* iph_api;
    IPH_API* orig_iph_api;
    IPH_API* outer_iph_api;
    IPH_API* outer_orig_iph_api;

    int family;
    int orig_family;
    int outer_family;
    //^^^-----------------------------

    uint32_t packet_flags;      /* special flags for the packet */
    uint32_t xtradata_mask;

    uint16_t proto_bits;

    //vvv-----------------------------
    uint16_t dsize;             /* packet payload size */
    uint16_t ip_dsize;          /* IP payload size */
    uint16_t alt_dsize;         /* the dsize of a packet before munging (used for log)*/
    uint16_t actual_ip_len;     /* for logging truncated pkts (usually by small snaplen)*/
    uint16_t outer_ip_dsize;    /* Outer IP payload size */
    //^^^-----------------------------

    uint16_t frag_offset;       /* fragment offset number */
    uint16_t ip_frag_len;
    uint16_t ip_options_len;
    uint16_t tcp_options_len;

    //vvv-----------------------------
    uint16_t sp;                /* source port (TCP/UDP) */
    uint16_t dp;                /* dest port (TCP/UDP) */
    uint16_t orig_sp;           /* source port (TCP/UDP) of original datagram */
    uint16_t orig_dp;           /* dest port (TCP/UDP) of original datagram */
    //^^^-----------------------------
    // and so on ...

    int16_t application_protocol_ordinal;

    uint8_t frag_flag;          /* flag to indicate a fragmented packet */
    uint8_t mf;                 /* more fragments flag */
    uint8_t df;                 /* don't fragment flag */
    uint8_t rf;                 /* IP reserved bit */

    uint8_t ip_option_count;    /* number of options in this packet */
    uint8_t tcp_option_count;
    uint8_t ip6_extension_count;
    uint8_t ip6_frag_index;

    uint8_t error_flags;        /* flags indicate checksum errors, bad TTLs, etc. */
    uint8_t encapsulated;
    uint8_t GTPencapsulated;
    uint8_t next_layer;         /* index into layers for next encap */

    // nothing after this point is zeroed ...
    ipv4::IpOptions ip_options[IP_OPTMAX];         /* ip options decode structure */
    Options tcp_options[TCP_OPTLENMAX];    /* tcp options decode struct */
    IP6Option ip6_extensions[IP6_EXTMAX];  /* IPv6 Extension References */

    const uint8_t *ip_frag_start;
    const uint8_t *ip_options_data;
    const uint8_t *tcp_options_data;

    const ipv6::IP6RawHdr* raw_ip6h;  // innermost raw ip6 header
    Layer layers[LAYER_MAX];    /* decoded encapsulations */

    ipv4::IP4Hdr inner_ip4h, inner_orig_ip4h;
    ipv6::IP6Hdr inner_ip6h, inner_orig_ip6h;
    ipv4::IP4Hdr outer_ip4h, outer_orig_ip4h;
    ipv6::IP6Hdr outer_ip6h, outer_orig_ip6h;

    MplsHdr mplsHdr;

    PseudoPacketType pseudo_type;    // valid only when PKT_PSEUDO is set
    uint16_t max_dsize;

    /**policyId provided in configuration file. Used for correlating configuration
     * with event output
     */
    uint16_t user_policy_id;

    uint32_t iplist_id;
    unsigned char iprep_layer;

    uint8_t ps_proto;  // Used for portscan and unified2 logging

};

#define PKT_ZERO_LEN offsetof(Packet, ip_options)

#define PROTO_BIT__NONE     0x0000
#define PROTO_BIT__IP       0x0001
#define PROTO_BIT__ARP      0x0002
#define PROTO_BIT__TCP      0x0004
#define PROTO_BIT__UDP      0x0008
#define PROTO_BIT__ICMP     0x0010
#define PROTO_BIT__TEREDO   0x0020
#define PROTO_BIT__GTP      0x0040
#define PROTO_BIT__MPLS     0x0080
#define PROTO_BIT__VLAN     0x0100
#define PROTO_BIT__ETH      0x0200
#define PROTO_BIT__OTHER    0x8000
#define PROTO_BIT__ALL      0xffff

#define IsIP(p) (IPH_IS_VALID(p))
#define IsTCP(p) (IsIP(p) && p->tcph)
#define IsICMP(p) (IsIP(p) && p->icmph)
#define GET_PKT_SEQ(p) (ntohl(p->tcph->th_seq))

/* Macros to deal with sequence numbers - p810 TCP Illustrated vol 2 */
#define SEQ_LT(a,b)  ((int)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int)((a) - (b)) >= 0)
#define SEQ_EQ(a,b)  ((int)((a) - (b)) == 0)

#define BIT(i) (0x1 << (i-1))

static inline int PacketWasCooked(const Packet* p)
{
    return ( p->packet_flags & PKT_PSEUDO ) != 0;
}

static inline bool IsPortscanPacket(const Packet *p)
{
    return ( PacketWasCooked(p) && (p->pseudo_type == PSEUDO_PKT_PS));
}

static inline uint8_t GetEventProto(const Packet *p)
{
    if (IsPortscanPacket(p))
        return p->ps_proto;
    return IPH_IS_VALID(p) ? GET_IPH_PROTO(p) : 0;
}

static inline bool PacketHasFullPDU (const Packet* p)
{
    return ( (p->packet_flags & PKT_PDU_FULL) == PKT_PDU_FULL );
}

static inline bool PacketHasStartOfPDU (const Packet* p)
{
    return ( (p->packet_flags & PKT_PDU_HEAD) != 0 );
}

static inline bool PacketHasPAFPayload (const Packet* p)
{
    return ( (p->packet_flags & PKT_REBUILT_STREAM) || PacketHasFullPDU(p) );
}

static inline bool PacketIsRebuilt (const Packet* p)
{
    return ( (p->packet_flags & (PKT_REBUILT_STREAM|PKT_REBUILT_FRAG)) != 0 );
}

static inline void SetExtraData (Packet* p, uint32_t xid)
{
    p->xtradata_mask |= BIT(xid);
}

static inline bool is_ip4(const Packet *p)
{
  return p->family == AF_INET;
}

static inline bool is_ip6(const Packet *p)
{
  return p->family == AF_INET6;
}

static inline uint16_t EXTRACT_16BITS(const uint8_t* p)
{
    return ntohs(*(uint16_t*)(p));
}

#ifdef WORDS_MUSTALIGN

#if defined(__GNUC__)
/* force word-aligned ntohl parameter */
    static inline uint32_t EXTRACT_32BITS(const uint8_t* p)
    {
        uint32_t tmp;
        memmove(&tmp, p, sizeof(uint32_t));
        return ntohl(tmp);
    }
#endif /* __GNUC__ */

#else

/* allows unaligned ntohl parameter - dies w/SIGBUS on SPARCs */
    static inline uint32_t EXTRACT_32BITS(const uint8_t* p)
    {
        return ntohl(*(uint32_t *)p);
    }
#endif /* WORDS_MUSTALIGN */

#endif

