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

#ifndef PROTOCOLS_PACKET_H
#define PROTOCOLS_PACKET_H

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

#include "framework/codec.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/mpls.h"
#include "protocols/ip.h"
#include "protocols/layer.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"


/*  D E F I N E S  ************************************************************/

/* packet status flags */
#if 0
#define PKT_TRUST            0x00000001  /* this packet should fallback to being whitelisted if no other verdict was specified */
                                         /* this flag must equal DECODE_PKT_TRUST*/
#define PKT_FRAG             0x00000002  /* flag to indicate a fragmented packet */
                                         /* this flag must equal DECODE_FRAG */
#define PKT_FRAG_MF          0x00000004  /* flag to indicate the 'more frag' flag is set */
                                         /* this flag must be equal to DECODE_MF */
#endif

#define PKT_REBUILT_FRAG     0x00000008  /* is a rebuilt fragment */
#define PKT_REBUILT_STREAM   0x00000010  /* is a rebuilt stream */
#define PKT_STREAM_UNEST_UNI 0x00000020  /* is from an unestablished stream and
                                          * we've only seen traffic in one direction */
#define PKT_STREAM_EST       0x00000040  /* is from an established stream */

#define PKT_STREAM_INSERT    0x00000080  /* this packet has been queued for stream reassembly */
#define PKT_STREAM_TWH       0x00000100  /* packet completes the 3-way handshake */
#define PKT_FROM_SERVER      0x00000200  /* this packet came from the server
                                            side of a connection (TCP) */
#define PKT_FROM_CLIENT      0x00000400  /* this packet came from the client
                                            side of a connection (TCP) */

#define PKT_PDU_HEAD         0x00000800  /* start of PDU */
#define PKT_PDU_TAIL         0x00001000  /* end of PDU */
#define PKT_HTTP_DECODE      0x00002000  /* this packet has normalized http */

#define PKT_ALLOW_MULTIPLE_DETECT 0x00004000  /* packet has either pipelined mime attachements */
                                              /* or pipeline http requests */
#define PKT_PAYLOAD_OBFUSCATE     0x00008000

#define PKT_STATELESS        0x00010000  /* Packet has matched a stateless rule */
#define PKT_PASS_RULE        0x00020000  /* this packet has matched a pass rule */
#define PKT_IP_RULE          0x00040000  /* this packet is being evaluated against an IP rule */
#define PKT_IP_RULE_2ND      0x00080000  /* this packet is being evaluated against an IP rule */

#define PKT_PSEUDO           0x00100000  /* is a pseudo packet */
#define PKT_MODIFIED         0x00200000  /* packet had normalizations, etc. */
#define PKT_RESIZED          0x00600000  /* packet has new size; must set modified too */

// neither of these flags will be set for (full) retransmissions or non-data segments
// a partial overlap results in out of sequence condition
// out of sequence condition is sticky
#define PKT_STREAM_ORDER_OK  0x00800000  /* this segment is in order, w/o gaps */
#define PKT_STREAM_ORDER_BAD 0x01000000  /* this stream had at least one gap */

#define PKT_FILE_EVENT_SET   0x02000000
#define PKT_IGNORE           0x04000000  /* this packet should be ignored, based on port */
#define PKT_UNUSED_FLAGS     0xf8000000

// 0x40000000 are available
#define PKT_PDU_FULL (PKT_PDU_HEAD | PKT_PDU_TAIL)


enum PseudoPacketType{
    PSEUDO_PKT_IP,
    PSEUDO_PKT_TCP,
    PSEUDO_PKT_DCE_RPKT,
    PSEUDO_PKT_DCE_SEG,
    PSEUDO_PKT_DCE_FRAG,
    PSEUDO_PKT_SMB_SEG,
    PSEUDO_PKT_SMB_TRANS,
    PSEUDO_PKT_PS,
    PSEUDO_PKT_SDF,
    PSEUDO_PKT_MAX
} ;


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

constexpr int32_t MAX_PORTS = 65536;
constexpr uint16_t NUM_IP_PROTOS = 256;
constexpr int16_t SFTARGET_UNKNOWN_PROTOCOL = -1;
constexpr uint8_t IP_OPTMAX = 40;
constexpr uint8_t TCP_OPTLENMAX = 40; /* (((2^4) - 1) * 4  - TCP_HEADER_LEN) */
constexpr uint8_t IP6_EXTMAX = 8;
constexpr uint8_t MIN_TTL = 64;
constexpr uint8_t MAX_TTL = 255;
constexpr uint8_t LAYER_MAX = 32;



/*  D A T A  S T R U C T U R E S  *********************************************/
class Flow;


struct Packet
{
    Flow* flow;   /* for session tracking */



    uint32_t packet_flags;      /* special flags for the packet */
    uint32_t xtradata_mask;
    uint16_t proto_bits;        /* protocols contained within this packet */
    int16_t application_protocol_ordinal;


    uint16_t alt_dsize;         /* the dsize of a packet before munging (used for log)*/
    uint8_t num_layers;         /* index into layers for next encap */


    // nothing after this point is zeroed ...

    // Everything beyond this point is set by PacketManager::decode()
    const DAQ_PktHdr_t *pkth;    // packet meta data
    const uint8_t *pkt;         // raw packet data

    // These are both set before PacketManager::decode() returns
    const uint8_t* data;        /* packet payload pointer */
    uint16_t dsize;             /* packet payload size */

    SnortData ptrs; // convenience pointers used throughout Snort++
    Layer layers[LAYER_MAX];    /* decoded encapsulations */


    PseudoPacketType pseudo_type;    // valid only when PKT_PSEUDO is set
    uint16_t max_dsize;

    /**policyId provided in configuration file. Used for correlating configuration
     * with event output
     */
    uint16_t user_policy_id;

    uint32_t iplist_id;

    uint8_t ps_proto;  // Used for portscan and unified2 logging

    /*  Access methods */

    inline uint8_t type() const
    { return ptrs.packet_type; }
};

#define PKT_ZERO_LEN offsetof(Packet, pkth)



#define IsIP(p) (p->ptrs.ip_api.is_valid())
#define IsTCP(p) (IsIP(p) && p->ptrs.tcph)
#define IsICMP(p) (IsIP(p) && p->ptrs.icmph)
#define GET_PKT_SEQ(p) (ntohl(p->ptrs.tcph->th_seq))

/* Macros to deal with sequence numbers - p810 TCP Illustrated vol 2 */
#define SEQ_LT(a,b)  ((int)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int)((a) - (b)) >= 0)
#define SEQ_EQ(a,b)  ((int)((a) - (b)) == 0)

#define BIT(i) (0x1 << (i-1))

static inline int PacketWasCooked(const Packet* const p)
{ return ( p->packet_flags & PKT_PSEUDO ) != 0; }

static inline bool IsPortscanPacket(const Packet* const p)
{ return ( PacketWasCooked(p) && (p->pseudo_type == PSEUDO_PKT_PS)); }

static inline uint8_t GetEventProto(const Packet* const p)
{
    if (IsPortscanPacket(p))
        return p->ps_proto;
    return p->ptrs.ip_api.proto(); // return 0 if invalid
}

static inline bool PacketHasFullPDU (const Packet* const p)
{ return ( (p->packet_flags & PKT_PDU_FULL) == PKT_PDU_FULL ); }

static inline bool PacketHasStartOfPDU (const Packet* const p)
{ return ( (p->packet_flags & PKT_PDU_HEAD) != 0 ); }

static inline bool PacketHasPAFPayload (const Packet* const p)
{ return ( (p->packet_flags & PKT_REBUILT_STREAM) || PacketHasFullPDU(p) ); }

static inline bool PacketIsRebuilt (const Packet* const p)
{ return ( (p->packet_flags & (PKT_REBUILT_STREAM|PKT_REBUILT_FRAG)) != 0 ); }

static inline void SetExtraData (Packet* p, const uint32_t xid)
{ p->xtradata_mask |= BIT(xid); }

static inline uint16_t EXTRACT_16BITS(const uint8_t* const p)
{ return ntohs(*(uint16_t*)(p)); }

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
    { return ntohl(*(uint32_t *)p); }
#endif /* WORDS_MUSTALIGN */

#endif
