/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

#ifndef DECODE_H
#define DECODE_H

/*  I N C L U D E S  **********************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/in_systm.h>

#ifndef IFNAMSIZ
#define IFNAMESIZ MAX_ADAPTER_NAME
#endif

extern "C" {
#include <daq.h>
#include <sfbpf_dlt.h>
}

#include "snort_types.h"
#include "protocols/packet.h"
#include "profiler.h"

/*  D E F I N E S  ************************************************************/

#define ETHERNET_MTU                  1500
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_PPPoE_DISC      0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPoE_SESS      0x8864 /* session stage */
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_LOOP            0x9000
#define ETHERNET_TYPE_MPLS_UNICAST    0x8847
#define ETHERNET_TYPE_MPLS_MULTICAST  0x8848
#define ETHERNET_TYPE_ERSPAN_TYPE2    0x88be
#define ETHERNET_TYPE_ERSPAN_TYPE3    0x22eb

#define ETH_DSAP_SNA                  0x08    /* SNA */
#define ETH_SSAP_SNA                  0x00    /* SNA */
#define ETH_DSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_SSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_DSAP_IP                   0xaa    /* IP */
#define ETH_SSAP_IP                   0xaa    /* IP */

#define ETH_ORG_CODE_ETHR              0x000000    /* Encapsulated Ethernet */
#define ETH_ORG_CODE_CDP               0x00000c    /* Cisco Discovery Proto */

#define ETHERNET_HEADER_LEN             14
#define ETHERNET_MAX_LEN_ENCAP          1518    /* 802.3 (+LLC) or ether II ? */
#define PPPOE_HEADER_LEN                6

#define VLAN_HEADER_LEN                  4

#ifndef NO_NON_ETHER_DECODER
#define MINIMAL_TOKENRING_HEADER_LEN    22
#define MINIMAL_IEEE80211_HEADER_LEN    10    /* Ack frames and others */
#define IEEE802_11_DATA_HDR_LEN         24    /* Header for data packets */
#define TR_HLEN                         MINIMAL_TOKENRING_HEADER_LEN
#define TOKENRING_LLC_LEN                8
#define SLIP_HEADER_LEN                 16

/* Frame type/subype combinations with version = 0 */
        /*** FRAME TYPE *****  HEX ****  SUBTYPE TYPE  DESCRIPT ********/
#define WLAN_TYPE_MGMT_ASREQ   0x0      /* 0000    00  Association Req */
#define WLAN_TYPE_MGMT_ASRES   0x10     /* 0001    00  Assocaition Res */
#define WLAN_TYPE_MGMT_REREQ   0x20     /* 0010    00  Reassoc. Req.   */
#define WLAN_TYPE_MGMT_RERES   0x30     /* 0011    00  Reassoc. Resp.  */
#define WLAN_TYPE_MGMT_PRREQ   0x40     /* 0100    00  Probe Request   */
#define WLAN_TYPE_MGMT_PRRES   0x50     /* 0101    00  Probe Response  */
#define WLAN_TYPE_MGMT_BEACON  0x80     /* 1000    00  Beacon          */
#define WLAN_TYPE_MGMT_ATIM    0x90     /* 1001    00  ATIM message    */
#define WLAN_TYPE_MGMT_DIS     0xa0     /* 1010    00  Disassociation  */
#define WLAN_TYPE_MGMT_AUTH    0xb0     /* 1011    00  Authentication  */
#define WLAN_TYPE_MGMT_DEAUTH  0xc0     /* 1100    00  Deauthentication*/

#define WLAN_TYPE_CONT_PS      0xa4     /* 1010    01  Power Save      */
#define WLAN_TYPE_CONT_RTS     0xb4     /* 1011    01  Request to send */
#define WLAN_TYPE_CONT_CTS     0xc4     /* 1100    01  Clear to sene   */
#define WLAN_TYPE_CONT_ACK     0xd4     /* 1101    01  Acknowledgement */
#define WLAN_TYPE_CONT_CFE     0xe4     /* 1110    01  Cont. Free end  */
#define WLAN_TYPE_CONT_CFACK   0xf4     /* 1111    01  CF-End + CF-Ack */

#define WLAN_TYPE_DATA_DATA    0x08     /* 0000    10  Data            */
#define WLAN_TYPE_DATA_DTCFACK 0x18     /* 0001    10  Data + CF-Ack   */
#define WLAN_TYPE_DATA_DTCFPL  0x28     /* 0010    10  Data + CF-Poll  */
#define WLAN_TYPE_DATA_DTACKPL 0x38     /* 0011    10  Data+CF-Ack+CF-Pl */
#define WLAN_TYPE_DATA_NULL    0x48     /* 0100    10  Null (no data)  */
#define WLAN_TYPE_DATA_CFACK   0x58     /* 0101    10  CF-Ack (no data)*/
#define WLAN_TYPE_DATA_CFPL    0x68     /* 0110    10  CF-Poll (no data)*/
#define WLAN_TYPE_DATA_ACKPL   0x78     /* 0111    10  CF-Ack+CF-Poll  */

/*** Flags for IEEE 802.11 Frame Control ***/
/* The following are designed to be bitwise-AND-d in an 8-bit u_char */
#define WLAN_FLAG_TODS      0x0100    /* To DS Flag   10000000 */
#define WLAN_FLAG_FROMDS    0x0200    /* From DS Flag 01000000 */
#define WLAN_FLAG_FRAG      0x0400    /* More Frag    00100000 */
#define WLAN_FLAG_RETRY     0x0800    /* Retry Flag   00010000 */
#define WLAN_FLAG_PWRMGMT   0x1000    /* Power Mgmt.  00001000 */
#define WLAN_FLAG_MOREDAT   0x2000    /* More Data    00000100 */
#define WLAN_FLAG_WEP       0x4000    /* Wep Enabled  00000010 */
#define WLAN_FLAG_ORDER     0x8000    /* Strict Order 00000001 */

/* IEEE 802.1x eapol types */
#define EAPOL_TYPE_EAP      0x00      /* EAP packet */
#define EAPOL_TYPE_START    0x01      /* EAPOL start */
#define EAPOL_TYPE_LOGOFF   0x02      /* EAPOL Logoff */
#define EAPOL_TYPE_KEY      0x03      /* EAPOL Key */
#define EAPOL_TYPE_ASF      0x04      /* EAPOL Encapsulated ASF-Alert */

/* Extensible Authentication Protocol Codes RFC 2284*/
#define EAP_CODE_REQUEST    0x01
#define EAP_CODE_RESPONSE   0x02
#define EAP_CODE_SUCCESS    0x03
#define EAP_CODE_FAILURE    0x04
/* EAP Types */
#define EAP_TYPE_IDENTITY   0x01
#define EAP_TYPE_NOTIFY     0x02
#define EAP_TYPE_NAK        0x03
#define EAP_TYPE_MD5        0x04
#define EAP_TYPE_OTP        0x05
#define EAP_TYPE_GTC        0x06
#define EAP_TYPE_TLS        0x0d
#endif  // NO_NON_ETHER_DECODER

/* Cisco HDLC header values */
#define CHDLC_HEADER_LEN        4
#define CHDLC_ADDR_UNICAST      0x0f
#define CHDLC_ADDR_MULTICAST    0x8f
#define CHDLC_ADDR_BROADCAST    0xff
#define CHDLC_CTRL_UNNUMBERED   0x03

/* Teredo values */
#define TEREDO_PORT 3544
#define TEREDO_INDICATOR_ORIGIN 0x00
#define TEREDO_INDICATOR_ORIGIN_LEN 8
#define TEREDO_INDICATOR_AUTH 0x01
#define TEREDO_INDICATOR_AUTH_MIN_LEN 13
#define TEREDO_MIN_LEN 2

/* GTP values */

#define GTP_MIN_LEN 8
#define GTP_V0_HEADER_LEN 20
#define GTP_V1_HEADER_LEN 12
/* ESP constants */
#define ESP_HEADER_LEN 8
#define ESP_AUTH_DATA_LEN 12
#define ESP_TRAILER_LEN 2

#define MAX_PORTS 65536

/* ppp header structure
 *
 * Actually, this is the header for RFC1332 Section 3
 * IPCP Configuration Options for sending IP datagrams over a PPP link
 *
 */
struct ppp_header {
    unsigned char  address;
    unsigned char  control;
    unsigned short protocol;
};

#ifndef PPP_HDRLEN
    #define PPP_HDRLEN          sizeof(struct ppp_header)
#endif

#define PPP_IP         0x0021        /* Internet Protocol */
#define PPP_IPV6       0x0057        /* Internet Protocol v6 */
#define PPP_VJ_COMP    0x002d        /* VJ compressed TCP/IP */
#define PPP_VJ_UCOMP   0x002f        /* VJ uncompressed TCP/IP */
#define PPP_IPX        0x002b        /* Novell IPX Protocol */

/* otherwise defined in /usr/include/ppp_defs.h */
#ifndef PPP_MTU
    #define PPP_MTU                 1500
#endif

/* NULL aka LoopBack interfaces */
#define NULL_HDRLEN             4

/* enc interface */
struct enc_header {
    uint32_t af;
    uint32_t spi;
    uint32_t flags;
};
#define ENC_HEADER_LEN          12

/* otherwise defined in /usr/include/ppp_defs.h */
#define IP_HEADER_LEN           20
#define TCP_HEADER_LEN          20
#define UDP_HEADER_LEN          8
#define ICMP_HEADER_LEN         4
#define ICMP_NORMAL_LEN         8

#define IP_OPTMAX               40
#define IP6_EXTMAX               8
#define TCP_OPTLENMAX           40 /* (((2^4) - 1) * 4  - TCP_HEADER_LEN) */

#ifndef IP_MAXPACKET
#define IP_MAXPACKET    65535        /* maximum packet size */
#endif /* IP_MAXPACKET */


/* http://www.iana.org/assignments/ipv6-parameters
 *
 * IPv6 Options (not Extension Headers)
 */
#define IP6_OPT_TUNNEL_ENCAP    0x04
#define IP6_OPT_QUICK_START     0x06
#define IP6_OPT_CALIPSO         0x07
#define IP6_OPT_HOME_ADDRESS    0xC9
#define IP6_OPT_ENDPOINT_IDENT  0x8A

// these are bits in th_flags:
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_RES2 TH_ECE  // TBD TH_RES* should be deleted (see log.c)
#define TH_RES1 TH_CWR
#define TH_NORESERVED (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)

// these are bits in th_offx2:
#define TH_RSV  0x0E  // reserved bits
#define TH_NS   0x01  // ECN nonce bit

/* http://www.iana.org/assignments/tcp-parameters
 *
 * tcp options stuff. used to be in <netinet/tcp.h> but it breaks
 * things on AIX
 */
#define TCPOPT_EOL              0   /* End of Option List [RFC793] */
#define TCPOLEN_EOL             1   /* Always one byte */

#define TCPOPT_NOP              1   /* No-Option [RFC793] */
#define TCPOLEN_NOP             1   /* Always one byte */

#define TCPOPT_MAXSEG           2   /* Maximum Segment Size [RFC793] */
#define TCPOLEN_MAXSEG          4   /* Always 4 bytes */

#define TCPOPT_WSCALE           3   /* Window scaling option [RFC1323] */
#define TCPOLEN_WSCALE          3   /* 1 byte with logarithmic values */

#define TCPOPT_SACKOK           4    /* Experimental [RFC2018]*/
#define TCPOLEN_SACKOK          2

#define TCPOPT_SACK             5    /* Experimental [RFC2018] variable length */

#define TCPOPT_ECHO             6    /* Echo (obsoleted by option 8)      [RFC1072] */
#define TCPOLEN_ECHO            6    /* 6 bytes  */

#define TCPOPT_ECHOREPLY        7    /* Echo Reply (obsoleted by option 8)[RFC1072] */
#define TCPOLEN_ECHOREPLY       6    /* 6 bytes  */

#define TCPOPT_TIMESTAMP        8   /* Timestamp [RFC1323], 10 bytes */
#define TCPOLEN_TIMESTAMP       10

#define TCPOPT_PARTIAL_PERM     9   /* Partial Order Permitted/ Experimental [RFC1693] */
#define TCPOLEN_PARTIAL_PERM    2   /* Partial Order Permitted/ Experimental [RFC1693] */

#define TCPOPT_PARTIAL_SVC      10  /*  Partial Order Profile [RFC1693] */
#define TCPOLEN_PARTIAL_SVC     3   /*  3 bytes long -- Experimental */

/* atleast decode T/TCP options... */
#define TCPOPT_CC               11  /*  T/TCP Connection count  [RFC1644] */
#define TCPOPT_CC_NEW           12  /*  CC.NEW [RFC1644] */
#define TCPOPT_CC_ECHO          13  /*  CC.ECHO [RFC1644] */
#define TCPOLEN_CC             6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_NEW         6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_ECHO        6  /* page 17 of rfc1644 */

#define TCPOPT_ALTCSUM          15  /* TCP Alternate Checksum Data [RFC1146], variable length */
#define TCPOPT_SKEETER          16  /* Skeeter [Knowles] */
#define TCPOPT_BUBBA            17  /* Bubba   [Knowles] */

#define TCPOPT_TRAILER_CSUM     18  /* Trailer Checksum Option [Subbu & Monroe] */
#define TCPOLEN_TRAILER_CSUM  3

#define TCPOPT_MD5SIG           19  /* MD5 Signature Option [RFC2385] */
#define TCPOLEN_MD5SIG        18

/* Space Communications Protocol Standardization */
#define TCPOPT_SCPS             20  /* Capabilities [Scott] */
#define TCPOPT_SELNEGACK        21  /* Selective Negative Acknowledgements [Scott] */
#define TCPOPT_RECORDBOUND         22  /* Record Boundaries [Scott] */
#define TCPOPT_CORRUPTION          23  /* Corruption experienced [Scott] */

#define TCPOPT_SNAP                24  /* SNAP [Sukonnik] -- anyone have info?*/
#define TCPOPT_UNASSIGNED          25  /* Unassigned (released 12/18/00) */
#define TCPOPT_COMPRESSION         26  /* TCP Compression Filter [Bellovin] */
/* http://www.research.att.com/~smb/papers/draft-bellovin-tcpcomp-00.txt*/

#define TCPOPT_AUTH   29  /* [RFC5925] - The TCP Authentication Option
                             Intended to replace MD5 Signature Option [RFC2385] */

#define TCP_OPT_TRUNC -1
#define TCP_OPT_BADLEN -2

/* Why are these lil buggers here? Never Used. -- cmg */
#define TCPOLEN_TSTAMP_APPA     (TCPOLEN_TIMESTAMP+2)    /* appendix A / rfc 1323 */
#define TCPOPT_TSTAMP_HDR    \
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

/*
 * Default maximum segment size for TCP.
 * With an IP MSS of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */

#ifndef TCP_MSS
    #define    TCP_MSS      512
#endif

#ifndef TCP_MAXWIN
    #define    TCP_MAXWIN   65535    /* largest value for (unscaled) window */
#endif

#ifndef TCP_MAX_WINSHIFT
    #define TCP_MAX_WINSHIFT    14    /* maximum window shift */
#endif

/*
 * User-settable options (used with setsockopt).
 */
#ifndef TCP_NODELAY
    #define    TCP_NODELAY   0x01    /* don't delay send to coalesce packets */
#endif

#ifndef TCP_MAXSEG
    #define    TCP_MAXSEG    0x02    /* set maximum segment size */
#endif

#define SOL_TCP        6    /* TCP level */



#define L2TP_PORT           1701
#define DHCP_CLIENT_PORT    68
#define DHCP_SERVER_PORT    67

#ifndef NO_NON_ETHER_DECODER
/* Start Token Ring */
#define TR_ALEN             6        /* octets in an Ethernet header */
#define IPARP_SAP           0xaa

#define AC                  0x10
#define LLC_FRAME           0x40

#define TRMTU                      2000    /* 2000 bytes            */
#define TR_RII                     0x80
#define TR_RCF_DIR_BIT             0x80
#define TR_RCF_LEN_MASK            0x1f00
#define TR_RCF_BROADCAST           0x8000    /* all-routes broadcast   */
#define TR_RCF_LIMITED_BROADCAST   0xC000    /* single-route broadcast */
#define TR_RCF_FRAME2K             0x20
#define TR_RCF_BROADCAST_MASK      0xC000
/* End Token Ring */

/* Start FDDI */
#define FDDI_ALLC_LEN                   13
#define FDDI_ALEN                       6
#define FDDI_MIN_HLEN                   (FDDI_ALLC_LEN + 3)

#define FDDI_DSAP_SNA                   0x08    /* SNA */
#define FDDI_SSAP_SNA                   0x00    /* SNA */
#define FDDI_DSAP_STP                   0x42    /* Spanning Tree Protocol */
#define FDDI_SSAP_STP                   0x42    /* Spanning Tree Protocol */
#define FDDI_DSAP_IP                    0xaa    /* IP */
#define FDDI_SSAP_IP                    0xaa    /* IP */

#define FDDI_ORG_CODE_ETHR              0x000000    /* Encapsulated Ethernet */
#define FDDI_ORG_CODE_CDP               0x00000c    /* Cisco Discovery
                             * Proto(?) */

#define ETHERNET_TYPE_CDP               0x2000    /* Cisco Discovery Protocol */
/* End FDDI */
#endif  // NO_NON_ETHER_DECODER

#define ARPOP_REQUEST   1    /* ARP request                  */
#define ARPOP_REPLY     2    /* ARP reply                    */
#define ARPOP_RREQUEST  3    /* RARP request                 */
#define ARPOP_RREPLY    4    /* RARP reply                   */

/* PPPoE types */
#define PPPoE_CODE_SESS 0x00 /* PPPoE session */
#define PPPoE_CODE_PADI 0x09 /* PPPoE Active Discovery Initiation */
#define PPPoE_CODE_PADO 0x07 /* PPPoE Active Discovery Offer */
#define PPPoE_CODE_PADR 0x19 /* PPPoE Active Discovery Request */
#define PPPoE_CODE_PADS 0x65 /* PPPoE Active Discovery Session-confirmation */
#define PPPoE_CODE_PADT 0xa7 /* PPPoE Active Discovery Terminate */

/* PPPoE tag types */
#define PPPoE_TAG_END_OF_LIST        0x0000
#define PPPoE_TAG_SERVICE_NAME       0x0101
#define PPPoE_TAG_AC_NAME            0x0102
#define PPPoE_TAG_HOST_UNIQ          0x0103
#define PPPoE_TAG_AC_COOKIE          0x0104
#define PPPoE_TAG_VENDOR_SPECIFIC    0x0105
#define PPPoE_TAG_RELAY_SESSION_ID   0x0110
#define PPPoE_TAG_SERVICE_NAME_ERROR 0x0201
#define PPPoE_TAG_AC_SYSTEM_ERROR    0x0202
#define PPPoE_TAG_GENERIC_ERROR      0x0203

#define MPLS_PAYLOADTYPE_ETHERNET     1
#define MPLS_PAYLOADTYPE_IPV4         2
#define MPLS_PAYLOADTYPE_IPV6         3
#define MPLS_PAYLOADTYPE_ERROR       -1
#define DEFAULT_MPLS_PAYLOADTYPE      MPLS_PAYLOADTYPE_IPV4
#define DEFAULT_LABELCHAIN_LENGTH    -1

#define ICMP_ECHOREPLY          0    /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3    /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4    /* Source Quench                */
#define ICMP_REDIRECT           5    /* Redirect (change route)      */
#define ICMP_ECHO               8    /* Echo Request                 */
#define ICMP_ROUTER_ADVERTISE   9    /* Router Advertisement         */
#define ICMP_ROUTER_SOLICIT     10    /* Router Solicitation          */
#define ICMP_TIME_EXCEEDED      11    /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12    /* Parameter Problem            */
#define ICMP_TIMESTAMP          13    /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14    /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15    /* Information Request          */
#define ICMP_INFO_REPLY         16    /* Information Reply            */
#define ICMP_ADDRESS            17    /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18    /* Address Mask Reply           */
#define NR_ICMP_TYPES           18

/* Codes for ICMP UNREACHABLES */
#define ICMP_NET_UNREACH        0    /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1    /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2    /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3    /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4    /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5    /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_PKT_FILTERED_NET   9
#define ICMP_PKT_FILTERED_HOST  10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13    /* Packet filtered */
#define ICMP_PREC_VIOLATION     14    /* Precedence violation */
#define ICMP_PREC_CUTOFF        15    /* Precedence cut off */
#define NR_ICMP_UNREACH         15    /* instead of hardcoding immediate
                                       * value */

#define ICMP_REDIR_NET          0
#define ICMP_REDIR_HOST         1
#define ICMP_REDIR_TOS_NET      2
#define ICMP_REDIR_TOS_HOST     3

#define ICMP_TIMEOUT_TRANSIT    0
#define ICMP_TIMEOUT_REASSY     1

#define ICMP_PARAM_BADIPHDR     0
#define ICMP_PARAM_OPTMISSING   1
#define ICMP_PARAM_BAD_LENGTH   2

/* ip option type codes */
#ifndef IPOPT_EOL
    #define IPOPT_EOL            0x00
#endif

#ifndef IPOPT_NOP
    #define IPOPT_NOP            0x01
#endif

#ifndef IPOPT_RR
    #define IPOPT_RR             0x07
#endif

#ifndef IPOPT_RTRALT
    #define IPOPT_RTRALT         0x94
#endif

#ifndef IPOPT_TS
    #define IPOPT_TS             0x44
#endif

#ifndef IPOPT_SECURITY
    #define IPOPT_SECURITY       0x82
#endif

#ifndef IPOPT_LSRR
    #define IPOPT_LSRR           0x83
#endif

#ifndef IPOPT_LSRR_E
    #define IPOPT_LSRR_E         0x84
#endif

#ifndef IPOPT_ESEC
    #define IPOPT_ESEC           0x85
#endif

#ifndef IPOPT_SATID
    #define IPOPT_SATID          0x88
#endif

#ifndef IPOPT_SSRR
    #define IPOPT_SSRR           0x89
#endif


/* tcp option codes */
#define TOPT_EOL                0x00
#define TOPT_NOP                0x01
#define TOPT_MSS                0x02
#define TOPT_WS                 0x03
#define TOPT_TS                 0x08
#ifndef TCPOPT_WSCALE
    #define TCPOPT_WSCALE           3     /* window scale factor (rfc1072) */
#endif
#ifndef TCPOPT_SACKOK
    #define    TCPOPT_SACKOK        4     /* selective ack ok (rfc1072) */
#endif
#ifndef TCPOPT_SACK
    #define    TCPOPT_SACK          5     /* selective ack (rfc1072) */
#endif
#ifndef TCPOPT_ECHO
    #define TCPOPT_ECHO             6     /* echo (rfc1072) */
#endif
#ifndef TCPOPT_ECHOREPLY
    #define TCPOPT_ECHOREPLY        7     /* echo (rfc1072) */
#endif
#ifndef TCPOPT_TIMESTAMP
    #define TCPOPT_TIMESTAMP        8     /* timestamps (rfc1323) */
#endif
#ifndef TCPOPT_CC
    #define TCPOPT_CC               11    /* T/TCP CC options (rfc1644) */
#endif
#ifndef TCPOPT_CCNEW
    #define TCPOPT_CCNEW            12    /* T/TCP CC options (rfc1644) */
#endif
#ifndef TCPOPT_CCECHO
    #define TCPOPT_CCECHO           13    /* T/TCP CC options (rfc1644) */
#endif

#define EXTRACT_16BITS(p) ((u_short) ntohs (*(u_short *)(p)))

#ifdef WORDS_MUSTALIGN

#if defined(__GNUC__)
/* force word-aligned ntohl parameter */
    #define EXTRACT_32BITS(p)  ({ uint32_t __tmp; memmove(&__tmp, (p), sizeof(uint32_t)); (uint32_t) ntohl(__tmp);})
#endif /* __GNUC__ */

#else

/* allows unaligned ntohl parameter - dies w/SIGBUS on SPARCs */
    #define EXTRACT_32BITS(p) ((uint32_t) ntohl (*(uint32_t *)(p)))

#endif                /* WORDS_MUSTALIGN */

#if 0
FIXIT delete me
typedef struct s_pseudoheader
{
    uint32_t sip, dip;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t len;

} PSEUDO_HDR;
#endif

/* Default classification for decoder alerts */
#define DECODE_CLASS 25

typedef struct _DecoderFlags
{
    char decode_alerts;   /* if decode.c alerts are going to be enabled */
    char oversized_alert;   /* alert if garbage after tcp/udp payload */
    char oversized_drop;   /* alert if garbage after tcp/udp payload */
    char drop_alerts;     /* drop alerts from decoder */
    char tcpopt_experiment;  /* TcpOptions Decoder */
    char drop_tcpopt_experiment; /* Drop alerts from TcpOptions Decoder */
    char tcpopt_obsolete;    /* Alert on obsolete TCP options */
    char drop_tcpopt_obsolete; /* Drop on alerts from obsolete TCP options */
    char tcpopt_ttcp;        /* Alert on T/TCP options */
    char drop_tcpopt_ttcp;   /* Drop on alerts from T/TCP options */
    char tcpopt_decode;      /* alert on decoder inconsistencies */
    char drop_tcpopt_decode; /* Drop on alerts from decoder inconsistencies */
    char ipopt_decode;      /* alert on decoder inconsistencies */
    char drop_ipopt_decode; /* Drop on alerts from decoder inconsistencies */

    /* To be moved to the frag preprocessor once it supports IPv6 */
    char ipv6_bad_frag_pkt;
    char bsd_icmp_frag;
    char drop_bad_ipv6_frag;

} DecoderFlags;

#define        ALERTMSG_LENGTH 256


/*  P R O T O T Y P E S  ******************************************************/

// root decoders
void DecodeEthPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeNullPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeRawPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeRawPkt6(Packet *, const DAQ_PktHdr_t*, const uint8_t *);

// chained decoders
void DecodeARP(const uint8_t *, uint32_t, Packet *);
void DecodeEthLoopback(const uint8_t *, uint32_t, Packet *);
void DecodeVlan(const uint8_t *, const uint32_t, Packet *);
void DecodePppPktEncapsulated(const uint8_t *, const uint32_t, Packet *);
void DecodePPPoEPkt(const uint8_t *, const uint32_t, Packet *);
void DecodeIP(const uint8_t *, const uint32_t, Packet *);
void DecodeIPV6(const uint8_t *, uint32_t, Packet *);
void DecodeTCP(const uint8_t *, const uint32_t, Packet *);
void DecodeUDP(const uint8_t *, const uint32_t, Packet *);
void DecodeICMP(const uint8_t *, const uint32_t, Packet *);
void DecodeICMP6(const uint8_t *, const uint32_t, Packet *);
void DecodeICMPEmbeddedIP(const uint8_t *, const uint32_t, Packet *);
void DecodeICMPEmbeddedIP6(const uint8_t *, const uint32_t, Packet *);
void DecodeIPOptions(const uint8_t *, uint32_t, Packet *);
void DecodeTCPOptions(const uint8_t *, uint32_t, Packet *);
void DecodeTeredo(const uint8_t *, uint32_t, Packet *);
void DecodeAH(const uint8_t *, uint32_t, Packet *);
void DecodeESP(const uint8_t *, uint32_t, Packet *);
void DecodeGTP(const uint8_t *, uint32_t, Packet *);

void DecodeGRE(const uint8_t *, const uint32_t, Packet *);
void DecodeTransBridging(const uint8_t *, const uint32_t, Packet *);
void DecoderAlertEncapsulated(Packet *, int, const char *, const uint8_t *, uint32_t);

int isPrivateIP(uint32_t addr);
void DecodeEthOverMPLS(const uint8_t*, const uint32_t, Packet*);
void DecodeMPLS(const uint8_t*, const uint32_t, Packet*);

#ifndef NO_NON_ETHER_DECODER
// root decoders
void DecodeTRPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeFDDIPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeLinuxSLLPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeIEEE80211Pkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeSlipPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeI4LRawIPPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeI4LCiscoIPPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeChdlcPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodePflog(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeOldPflog(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodePppPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodePppSerialPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);
void DecodeEncPkt(Packet *, const DAQ_PktHdr_t*, const uint8_t *);

// chained decoders
void DecodeEAP(const uint8_t *, const uint32_t, Packet *);
void DecodeEapol(const uint8_t *, uint32_t, Packet *);
void DecodeEapolKey(const uint8_t *, uint32_t, Packet *);
void DecodeIPX(const uint8_t *, uint32_t, Packet *);
#endif  // NO_NON_ETHER_DECODER

void BsdFragHashInit(int max);
void BsdFragHashCleanup(void);
void BsdFragHashReset(void);

#if defined(WORDS_MUSTALIGN) && !defined(__GNUC__)
uint32_t EXTRACT_32BITS (u_char *);
#endif /* WORDS_MUSTALIGN && !__GNUC__ */

/*Decode functions that need to be called once the policies are set */
extern void DecodePolicySpecific(Packet *);

void InitSynToMulticastDstIp(struct SnortConfig*);
void SynToMulticastDstIpDestroy( void );

#define SFTARGET_UNKNOWN_PROTOCOL -1

#ifdef PERF_PROFILING
extern THREAD_LOCAL PreprocStats decodePerfStats;
#endif

void decoder_sum();
void decoder_stats();

#endif

