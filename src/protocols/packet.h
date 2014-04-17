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

#include "snort_types.h"
#include "sfip/ipv6_port.h"
#include "sfip/sf_ip.h"
#include "sfip/sf_iph.h"

#include "codecs/layer.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/arp.h"


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

#define PKT_LOGGED           0x00100000  /* this packet has been logged */
#define PKT_PSEUDO           0x00200000  /* is a pseudo packet */
#define PKT_MODIFIED         0x00400000  /* packet had normalizations, etc. */
#define PKT_RESIZED          0x00800000  /* packet has new size; must set modified too */

// neither of these flags will be set for (full) retransmissions or non-data segments
// a partial overlap results in out of sequence condition
// out of sequence condition is sticky
#define PKT_STREAM_ORDER_OK  0x01000000  /* this segment is in order, w/o gaps */
#define PKT_STREAM_ORDER_BAD 0x02000000  /* this stream had at least one gap */
#define PKT_REASSEMBLED_OLD  0x04000000  /* for backwards compat with so rules */

#define PKT_IPREP_SOURCE_TRIGGERED  0x08000000
#define PKT_IPREP_DATA_SET          0x10000000
#define PKT_FILE_EVENT_SET          0x20000000
// 0x40000000 are available

#define PKT_PDU_FULL (PKT_PDU_HEAD | PKT_PDU_TAIL)

#define REASSEMBLED_PACKET_FLAGS (PKT_REBUILT_STREAM|PKT_REASSEMBLED_OLD)

typedef enum {
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
} PseudoPacketType;

/* error flags */
#define PKT_ERR_CKSUM_IP     0x01
#define PKT_ERR_CKSUM_TCP    0x02
#define PKT_ERR_CKSUM_UDP    0x04
#define PKT_ERR_CKSUM_ICMP   0x08
#define PKT_ERR_CKSUM_ANY    0x0F
#define PKT_ERR_BAD_TTL      0x10

/*  D A T A  S T R U C T U R E S  *********************************************/
struct Flow;

#ifndef NO_NON_ETHER_DECODER
/* Start Token Ring Data Structures */

#ifdef _MSC_VER
    /* Visual C++ pragma to disable warning messages about nonstandard bit field type */
    #pragma warning( disable : 4214 )
#endif

/* LLC structure */
typedef struct _Trh_llc
{
    uint8_t dsap;
    uint8_t ssap;
    uint8_t protid[3];
    uint16_t ethertype;
}        Trh_llc;

/* RIF structure
 * Linux/tcpdump patch defines tokenring header in dump way, since not
 * every tokenring header with have RIF data... we define it separately, and
 * a bit more split up
 */

#ifdef _MSC_VER
  /* Visual C++ pragma to disable warning messages about nonstandard bit field type */
  #pragma warning( disable : 4214 )
#endif


/* These are macros to use the bitlevel accesses in the Trh_Mr header

   they haven't been tested and they aren't used much so here is a
   listing of what used to be there

   #if defined(WORDS_BIGENDIAN)
      uint16_t bcast:3, len:5, dir:1, lf:3, res:4;
   #else
      uint16_t len:5,         length of RIF field, including RC itself
      bcast:3,       broadcast indicator
      res:4,         reserved
      lf:3,      largest frame size
      dir:1;         direction
*/

#define TRH_MR_BCAST(trhmr)  ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0xe000) >> 13)
#define TRH_MR_LEN(trhmr)    ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x1F00) >> 8)
#define TRH_MR_DIR(trhmr)    ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x0080) >> 7)
#define TRH_MR_LF(trhmr)     ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x0070) >> 4)
#define TRH_MR_RES(trhmr)     ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x000F))

typedef struct _Trh_mr
{
    uint16_t bcast_len_dir_lf_res; /* broadcast/res/framesize/direction */
    uint16_t rseg[8];
}       Trh_mr;
#ifdef _MSC_VER
  /* Visual C++ pragma to enable warning messages about nonstandard bit field type */
  #pragma warning( default : 4214 )
#endif

#define TR_ALEN             6        /* octets in an Ethernet header */
#define FDDI_ALEN           6

typedef struct _Trh_hdr
{
    uint8_t ac;        /* access control field */
    uint8_t fc;        /* frame control field */
    uint8_t daddr[TR_ALEN];    /* src address */
    uint8_t saddr[TR_ALEN];    /* dst address */
}        Trh_hdr;

#ifdef WIN32
    /* Visual C++ pragma to enable warning messages about nonstandard bit field type */
    #pragma warning( default : 4214 )
#endif
/* End Token Ring Data Structures */


/* Start FDDI Data Structures */

/* FDDI header is always this: -worm5er */
typedef struct _Fddi_hdr
{
    uint8_t fc;        /* frame control field */
    uint8_t daddr[FDDI_ALEN];  /* src address */
    uint8_t saddr[FDDI_ALEN];  /* dst address */
}         Fddi_hdr;

/* splitting the llc up because of variable lengths of the LLC -worm5er */
typedef struct _Fddi_llc_saps
{
    uint8_t dsap;
    uint8_t ssap;
}              Fddi_llc_saps;

/* I've found sna frames have two addition bytes after the llc saps -worm5er */
typedef struct _Fddi_llc_sna
{
    uint8_t ctrl_fld[2];
}             Fddi_llc_sna;

/* I've also found other frames that seem to have only one byte...  We're only
really intersted in the IP data so, until we want other, I'm going to say
the data is one byte beyond this frame...  -worm5er */
typedef struct _Fddi_llc_other
{
    uint8_t ctrl_fld[1];
}               Fddi_llc_other;

/* Just like TR the ip/arp data is setup as such: -worm5er */
typedef struct _Fddi_llc_iparp
{
    uint8_t ctrl_fld;
    uint8_t protid[3];
    uint16_t ethertype;
}               Fddi_llc_iparp;

/* End FDDI Data Structures */


/* 'Linux cooked captures' data
 * (taken from tcpdump source).
 */

#define SLL_HDR_LEN     16              /* total header length */
#define SLL_ADDRLEN     8               /* length of address field */
typedef struct _SLLHdr {
        uint16_t       sll_pkttype;    /* packet type */
        uint16_t       sll_hatype;     /* link-layer address type */
        uint16_t       sll_halen;      /* link-layer address length */
        uint8_t        sll_addr[SLL_ADDRLEN];  /* link-layer address */
        uint16_t       sll_protocol;   /* protocol */
} SLLHdr;


/*
 * Snort supports 3 versions of the OpenBSD pflog header:
 *
 * Pflog1_Hdr:  CVS = 1.3,  DLT_OLD_PFLOG = 17,  Length = 28
 * Pflog2_Hdr:  CVS = 1.8,  DLT_PFLOG     = 117, Length = 48
 * Pflog3_Hdr:  CVS = 1.12, DLT_PFLOG     = 117, Length = 64
 * Pflog3_Hdr:  CVS = 1.172, DLT_PFLOG     = 117, Length = 100
 *
 * Since they have the same DLT, Pflog{2,3}Hdr are distinguished
 * by their actual length.  The minimum required length excludes
 * padding.
 */
/* Old OpenBSD pf firewall pflog0 header
 * (information from pf source in kernel)
 * the rule, reason, and action codes tell why the firewall dropped it -fleck
 */

typedef struct _Pflog1_hdr
{
    uint32_t af;
    char intf[IFNAMSIZ];
    int16_t rule;
    uint16_t reason;
    uint16_t action;
    uint16_t dir;
} Pflog1Hdr;

#define PFLOG1_HDRLEN (sizeof(struct _Pflog1_hdr))

/*
 * Note that on OpenBSD, af type is sa_family_t. On linux, that's an unsigned
 * short, but on OpenBSD, that's a uint8_t, so we should explicitly use uint8_t
 * here.  - ronaldo
 */

#define PFLOG_RULELEN 16
#define PFLOG_PADLEN  3

typedef struct _Pflog2_hdr
{
    int8_t   length;
    uint8_t  af;
    uint8_t  action;
    uint8_t  reason;
    char     ifname[IFNAMSIZ];
    char     ruleset[PFLOG_RULELEN];
    uint32_t rulenr;
    uint32_t subrulenr;
    uint8_t  dir;
    uint8_t  pad[PFLOG_PADLEN];
} Pflog2Hdr;

#define PFLOG2_HDRLEN (sizeof(struct _Pflog2_hdr))
#define PFLOG2_HDRMIN (PFLOG2_HDRLEN - PFLOG_PADLEN)

typedef struct _Pflog3_hdr
{
    int8_t   length;
    uint8_t  af;
    uint8_t  action;
    uint8_t  reason;
    char     ifname[IFNAMSIZ];
    char     ruleset[PFLOG_RULELEN];
    uint32_t rulenr;
    uint32_t subrulenr;
    uint32_t uid;
    uint32_t pid;
    uint32_t rule_uid;
    uint32_t rule_pid;
    uint8_t  dir;
    uint8_t  pad[PFLOG_PADLEN];
} Pflog3Hdr;

#define PFLOG3_HDRLEN (sizeof(struct _Pflog3_hdr))
#define PFLOG3_HDRMIN (PFLOG3_HDRLEN - PFLOG_PADLEN)


typedef struct _Pflog4_hdr
{
    uint8_t  length;
    uint8_t  af;
    uint8_t  action;
    uint8_t  reason;
    char     ifname[IFNAMSIZ];
    char     ruleset[PFLOG_RULELEN];
    uint32_t rulenr;
    uint32_t subrulenr;
    uint32_t uid;
    uint32_t pid;
    uint32_t rule_uid;
    uint32_t rule_pid;
    uint8_t  dir;
    uint8_t  rewritten;
    uint8_t  pad[2];
    uint8_t saddr[16];
    uint8_t daddr[16];
    uint16_t sport;
    uint16_t dport;
} Pflog4Hdr;

#define PFLOG4_HDRLEN sizeof(struct _Pflog4_hdr)
#define PFLOG4_HDRMIN sizeof(struct _Pflog4_hdr)

/*
 * ssl_pkttype values.
 */

#define LINUX_SLL_HOST          0
#define LINUX_SLL_BROADCAST     1
#define LINUX_SLL_MULTICAST     2
#define LINUX_SLL_OTHERHOST     3
#define LINUX_SLL_OUTGOING      4

/* ssl protocol values */

#define LINUX_SLL_P_802_3       0x0001  /* Novell 802.3 frames without 802.2 LLC header */
#define LINUX_SLL_P_802_2       0x0004  /* 802.2 frames (not D/I/X Ethernet) */
#endif  // NO_NON_ETHER_DECODER


#ifdef _MSC_VER
  /* Visual C++ pragma to disable warning messages
   * about nonstandard bit field type
   */
  #pragma warning( disable : 4214 )
#endif

#define VTH_PRIORITY(vh)  ((ntohs((vh)->vth_pri_cfi_vlan) & 0xe000) >> 13)
#define VTH_CFI(vh)       ((ntohs((vh)->vth_pri_cfi_vlan) & 0x1000) >> 12)
#define VTH_VLAN(vh)      ((uint16_t)(ntohs((vh)->vth_pri_cfi_vlan) & 0x0FFF))

typedef struct _VlanTagHdr
{
    uint16_t vth_pri_cfi_vlan;
    uint16_t vth_proto;  /* protocol field... */
} VlanTagHdr;
#ifdef _MSC_VER
  /* Visual C++ pragma to enable warning messages about nonstandard bit field type */
  #pragma warning( default : 4214 )
#endif


typedef struct _EthLlc
{
    uint8_t dsap;
    uint8_t ssap;
} EthLlc;

typedef struct _EthLlcOther
{
    uint8_t ctrl;
    uint8_t org_code[3];
    uint16_t proto_id;
} EthLlcOther;

/* We must twiddle to align the offset the ethernet header and align
 * the IP header on solaris -- maybe this will work on HPUX too.
 */
#if defined (SOLARIS) || defined (SUNOS) || defined (__sparc__) || defined(__sparc64__) || defined (HPUX)
#define SPARC_TWIDDLE       2
#else
#define SPARC_TWIDDLE       0
#endif


#ifndef NO_NON_ETHER_DECODER
/*
 *  Wireless Header (IEEE 802.11)
 */
typedef struct _WifiHdr
{
  uint16_t frame_control;
  uint16_t duration_id;
  uint8_t  addr1[6];
  uint8_t  addr2[6];
  uint8_t  addr3[6];
  uint16_t seq_control;
  uint8_t  addr4[6];
} WifiHdr;
#endif  // NO_NON_ETHER_DECODER


/* Can't add any fields not in the real header here
   because of how the decoder uses structure overlaying */
#ifdef _MSC_VER
  /* Visual C++ pragma to disable warning messages
   * about nonstandard bit field type
   */
  #pragma warning( disable : 4214 )
#endif

/* tcpdump shows us the way to cross platform compatibility */
#define IP_VER(iph)    (((iph)->ip_verhl & 0xf0) >> 4)
#define IP_HLEN(iph)   ((iph)->ip_verhl & 0x0f)

/* we need to change them as well as get them */
#define SET_IP_VER(iph, value)  ((iph)->ip_verhl = (unsigned char)(((iph)->ip_verhl & 0x0f) | (value << 4)))
#define SET_IP_HLEN(iph, value)  ((iph)->ip_verhl = (unsigned char)(((iph)->ip_verhl & 0xf0) | (value & 0x0f)))

#define NUM_IP_PROTOS 256

/* Last updated 6/2/2010.
   Source: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml */
#define MIN_UNASSIGNED_IP_PROTO 143

#ifndef IPPROTO_IP_MOBILITY
#define IPPROTO_IP_MOBILITY     55
#endif
#ifndef IPPROTO_SUN_ND
#define IPPROTO_SUN_ND          77
#endif
#ifndef IPPROTO_PIM
#define IPPROTO_PIM             103
#endif
#ifndef IPPROTO_PGM
#define IPPROTO_PGM             113
#endif

#define IP_OPTMAX               40
#define IP6_EXTMAX               8
#define TCP_OPTLENMAX           40 /* (((2^4) - 1) * 4  - TCP_HEADER_LEN) */



#ifdef _MSC_VER
  /* Visual C++ pragma to enable warning messages about nonstandard bit field type */
  #pragma warning( default : 4214 )
#endif


/* Can't add any fields not in the real header here
   because of how the decoder uses structure overlaying */
#ifdef _MSC_VER
  /* Visual C++ pragma to disable warning
   * messages about nonstandard bit field type
   */
  #pragma warning( disable : 4214 )
#endif


/* GRE related stuff */
typedef struct _GREHdr
{
    uint8_t flags;
    uint8_t version;
    uint16_t ether_type;

} GREHdr;

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

#define GRE_TYPE_TRANS_BRIDGING 0x6558
#define GRE_TYPE_PPP            0x880B

#define GRE_HEADER_LEN 4
#define GRE_CHKSUM_LEN 2
#define GRE_OFFSET_LEN 2
#define GRE_KEY_LEN 4
#define GRE_SEQ_LEN 4
#define GRE_SRE_HEADER_LEN 4

#define GRE_CHKSUM(x)  (x->flags & 0x80)
#define GRE_ROUTE(x)   (x->flags & 0x40)
#define GRE_KEY(x)     (x->flags & 0x20)
#define GRE_SEQ(x)     (x->flags & 0x10)
#define GRE_SSR(x)     (x->flags & 0x08)
#define GRE_RECUR(x)   (x->flags & 0x07)
#define GRE_VERSION(x) (x->version & 0x07)
#define GRE_FLAGS(x)   (x->version & 0xF8)
#define GRE_PROTO(x)   ntohs(x->ether_type)

/* GRE version 1 used with PPTP */
#define GRE_V1_HEADER_LEN 8
#define GRE_V1_ACK_LEN    4
#define GRE_V1_FLAGS(x)   (x->version & 0x78)
#define GRE_V1_ACK(x)     (x->version & 0x80)

typedef struct _ERSpanType2Hdr
{
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t pad;
} ERSpanType2Hdr;

typedef struct _ERSpanType3Hdr
{
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t timestamp;
    uint16_t pad0;
    uint16_t pad1;
    uint32_t pad2;
    uint32_t pad3;
} ERSpanType3Hdr;

#define ERSPAN_VERSION(x) ((ntohs(x->ver_vlan) & 0xf000) >> 12)
#define ERSPAN_VLAN(x) (ntohs(x->ver_vlan) & 0x0fff)
#define ERSPAN_SPAN_ID(x) (ntohs(x->flags_spanId) & 0x03ff)
#define ERSPAN3_TIMESTAMP(x) (x->timestamp)

/* more macros for TCP offset */
#define TCP_OFFSET(tcph)        (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_X2(tcph)            ((tcph)->th_offx2 & 0x0f)

#define TCP_ISFLAGSET(tcph, flags) (((tcph)->th_flags & (flags)) == (flags))

/* we need to change them as well as get them */
#define SET_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define SET_TCP_X2(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

typedef struct _TCPHdr
{
    uint16_t th_sport;     /* source port */
    uint16_t th_dport;     /* destination port */
    uint32_t th_seq;       /* sequence number */
    uint32_t th_ack;       /* acknowledgement number */
    uint8_t th_offx2;      /* offset and reserved */
    uint8_t th_flags;
    uint16_t th_win;       /* window */
    uint16_t th_sum;       /* checksum */
    uint16_t th_urp;       /* urgent pointer */

}       TCPHdr;
#ifdef _MSC_VER
  /* Visual C++ pragma to enable warning messages
   * about nonstandard bit field type
   */
  #pragma warning( default : 4214 )
#endif



#ifndef NO_NON_ETHER_DECODER
typedef struct _EtherEapol
{
    uint8_t  version;  /* EAPOL proto version */
    uint8_t  eaptype;  /* EAPOL Packet type */
    uint16_t len;  /* Packet body length */
}         EtherEapol;

typedef struct _EAPHdr
{
    uint8_t code;
    uint8_t id;
    uint16_t len;
}         EAPHdr;

typedef struct _EapolKey
{
  uint8_t type;
  uint8_t length[2];
  uint8_t counter[8];
  uint8_t iv[16];
  uint8_t index;
  uint8_t sig[16];
}       EapolKey;
#endif  // NO_NON_ETHER_DECODER

typedef struct _Options
{
    uint8_t code;
    uint8_t len; /* length of the data section */
    const uint8_t *data;
} Options;




/* PPPoEHdr Header; eth::EtherHdr plus the PPPoE Header */
typedef struct _PPPoEHdr
{
    unsigned char ver_type;     /* pppoe version/type */
    unsigned char code;         /* pppoe code CODE_* */
    unsigned short session;     /* session id */
    unsigned short length;      /* payload length */
                                /* payload follows */
} PPPoEHdr;

/* PPPoE tag; the payload is a sequence of these */
typedef struct _PPPoE_Tag
{
    unsigned short type;    /* tag type TAG_* */
    unsigned short length;    /* tag length */
                            /* payload follows */
} PPPoE_Tag;

#define MPLS_HEADER_LEN    4
#define NUM_RESERVED_LABELS    16

typedef struct _MplsHdr
{
    uint32_t label;
    uint8_t  exp;
    uint8_t  bos;
    uint8_t  ttl;
} MplsHdr;

#define PGM_NAK_ERR -1
#define PGM_NAK_OK 0
#define PGM_NAK_VULN 1

typedef struct _PGM_NAK_OPT
{
    uint8_t type;     /* 02 = vuln */
    uint8_t len;
    uint8_t res[2];
    uint32_t seq[1];    /* could be many many more, but 1 is sufficient */
} PGM_NAK_OPT;

typedef struct _PGM_NAK
{
    uint32_t  seqnum;
    uint16_t  afil1;
    uint16_t  res1;
    uint32_t  src;
    uint16_t  afi2;
    uint16_t  res2;
    uint32_t  multi;
    PGM_NAK_OPT opt;
} PGM_NAK;

typedef struct _PGM_HEADER
{
    uint16_t srcport;
    uint16_t dstport;
    uint8_t  type;
    uint8_t  opt;
    uint16_t checksum;
    uint8_t  gsd[6];
    uint16_t length;
    PGM_NAK  nak;
} PGM_HEADER;


#define LAYER_MAX  32

struct Packet
{
    const DAQ_PktHdr_t *pkth;    // packet meta data
    const uint8_t *pkt;         // raw packet data

    //vvv------------------------------------------------
    // TODO convenience stuff to be refactored for layers
    //^^^------------------------------------------------

    //vvv-----------------------------
    EtherARP *ah;
    const eth::EtherHdr *eh;         /* standard TCP/IP/Ethernet/ARP headers */
    const VlanTagHdr *vh;
    EthLlc *ehllc;
    EthLlcOther *ehllcother;
    const PPPoEHdr *pppoeh;     /* Encapsulated PPP of Ether header */
    const GREHdr *greh;
    uint32_t *mpls;

    const IPHdr *iph, *orig_iph;/* and orig. headers for ICMP_*_UNREACH family */
    const IPHdr *inner_iph;     /* if IP-in-IP, this will be the inner IP header */
    const IPHdr *outer_iph;     /* if IP-in-IP, this will be the outer IP header */
    const TCPHdr *tcph, *orig_tcph;
    const udp::UDPHdr *udph, *orig_udph;
    const udp::UDPHdr *inner_udph;   /* if Teredo + UDP, this will be the inner UDP header */
    const udp::UDPHdr *outer_udph;   /* if Teredo + UDP, this will be the outer UDP header */
    const ICMPHdr *icmph, *orig_icmph;

    const uint8_t *data;        /* packet payload pointer */
    const uint8_t *ip_data;     /* IP payload pointer */
    const uint8_t *outer_ip_data;  /* Outer IP payload pointer */
    //^^^-----------------------------

    Flow* flow;   /* for tcp session tracking info... */
    void *fragtracker;          /* for ip fragmentation tracking info... */

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

#ifndef NO_NON_ETHER_DECODER
    const Fddi_hdr *fddihdr;    /* FDDI support headers */
    Fddi_llc_saps *fddisaps;
    Fddi_llc_sna *fddisna;
    Fddi_llc_iparp *fddiiparp;
    Fddi_llc_other *fddiother;

    const Trh_hdr *trh;         /* Token Ring support headers */
    Trh_llc *trhllc;
    Trh_mr *trhmr;

    Pflog1Hdr *pf1h;            /* OpenBSD pflog interface header - version 1 */
    Pflog2Hdr *pf2h;            /* OpenBSD pflog interface header - version 2 */
    Pflog3Hdr *pf3h;            /* OpenBSD pflog interface header - version 3 */
    Pflog4Hdr *pf4h;            /* OpenBSD pflog interface header - version 4 */

#ifdef DLT_LINUX_SLL
    const SLLHdr *sllh;         /* Linux cooked sockets header */
#endif
#ifdef DLT_IEEE802_11
    const WifiHdr *wifih;       /* wireless LAN header */
#endif
    const EtherEapol *eplh;     /* 802.1x EAPOL header */
    const EAPHdr *eaph;
    const uint8_t *eaptype;
    EapolKey *eapolk;
#endif

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
    uint16_t configPolicyId;
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


// Encoder && Decoder general structs

typedef struct
{
    uint32_t sip[4], dip[4];
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t len;
} pseudoheader6;


typedef struct
{
    uint32_t sip, dip;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t len;
} pseudoheader;


class PacketClass{

public:
    static 
    void PushLayer(Packet *p, const Codec *cd, const uint8_t *hdr_start, uint32_t len);


private:



};

#endif

