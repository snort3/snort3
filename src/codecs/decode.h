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

#ifndef DECODE_H
#define DECODE_H

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
#include "protocols/packet.h"
#include "profiler.h"
#include "protocols/mpls.h"





/*  D E F I N E S  ************************************************************/


#define ETH_DSAP_SNA                  0x08    /* SNA */
#define ETH_SSAP_SNA                  0x00    /* SNA */
#define ETH_DSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_SSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_DSAP_IP                   0xaa    /* IP */
#define ETH_SSAP_IP                   0xaa    /* IP */

#define ETH_ORG_CODE_ETHR              0x000000    /* Encapsulated Ethernet */
#define ETH_ORG_CODE_CDP               0x00000c    /* Cisco Discovery Proto */

#define ETHERNET_MAX_LEN_ENCAP          1518    /* 802.3 (+LLC) or ether II ? */


#define DEFAULT_MPLS_PAYLOADTYPE      MPLS_PAYLOADTYPE_IPV4
#define DEFAULT_LABELCHAIN_LENGTH    -1


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

/* otherwise defined in /usr/include/ppp_defs.h */
#ifndef PPP_MTU
    #define PPP_MTU                 1500
#endif

/* enc interface */
struct enc_header {
    uint32_t af;
    uint32_t spi;
    uint32_t flags;
};
#define ENC_HEADER_LEN          12


#define IP_OPTMAX               40
#define IP6_EXTMAX               8
#define TCP_OPTLENMAX           40 /* (((2^4) - 1) * 4  - TCP_HEADER_LEN) */






#define EXTRACT_16BITS(p) ((uint16_t) ntohs (*(uint16_t *)(p)))

#ifdef WORDS_MUSTALIGN

#if defined(__GNUC__)
/* force word-aligned ntohl parameter */
    #define EXTRACT_32BITS(p)  ({ uint32_t __tmp; memmove(&__tmp, (p), sizeof(uint32_t)); (uint32_t) ntohl(__tmp);})
#endif /* __GNUC__ */

#else

/* allows unaligned ntohl parameter - dies w/SIGBUS on SPARCs */
    #define EXTRACT_32BITS(p) ((uint32_t) ntohl (*(uint32_t *)(p)))

#endif                /* WORDS_MUSTALIGN */


/* Default classification for decoder alerts */
#define DECODE_CLASS 25

#define        ALERTMSG_LENGTH 256

/*  P R O T O T Y P E S  ******************************************************/

// root decoders

// chained decoders


void BsdFragHashInit(int max);
void BsdFragHashCleanup(void);
void BsdFragHashReset(void);

#if defined(WORDS_MUSTALIGN) && !defined(__GNUC__)
uint32_t EXTRACT_32BITS (u_char *);
#endif /* WORDS_MUSTALIGN && !__GNUC__ */

/*Decode functions that need to be called once the policies are set */
extern void DecodePolicySpecific(Packet *);

/* XXX not sure where this guy needs to live at the moment */
#if 0
typedef struct _PortList
{
    int ports[32];   /* 32 is kind of arbitrary */

    int num_entries;

} PortList;
#endif

#define SFTARGET_UNKNOWN_PROTOCOL -1

void decoder_sum();
void decoder_stats();



#endif

