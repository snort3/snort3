/* $Id: decode.c,v 1.285 2013-06-29 03:03:00 rcombs Exp $ */

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



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "generators.h"
#include "protocols/packet.h"  
#include "static_include.h"

#include "root_pflog.h"
#include "../decoder_includes.h"

namespace
{


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

struct Pflog1Hdr
{
    uint32_t af;
    char intf[IFNAMSIZ];
    int16_t rule;
    uint16_t reason;
    uint16_t action;
    uint16_t dir;
};

#define PFLOG1_HDRLEN (sizeof(struct _Pflog1_hdr))

/*
 * Note that on OpenBSD, af type is sa_family_t. On linux, that's an unsigned
 * short, but on OpenBSD, that's a uint8_t, so we should explicitly use uint8_t
 * here.  - ronaldo
 */

#define PFLOG_RULELEN 16
#define PFLOG_PADLEN  3

struct Pflog2Hdr
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
} ;

#define PFLOG2_HDRLEN (sizeof(struct _Pflog2_hdr))
#define PFLOG2_HDRMIN (PFLOG2_HDRLEN - PFLOG_PADLEN)

struct Pflog3Hdr
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
};

#define PFLOG3_HDRLEN (sizeof(struct _Pflog3_hdr))
#define PFLOG3_HDRMIN (PFLOG3_HDRLEN - PFLOG_PADLEN)


struct Pflog4Hdr
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
};

#define PFLOG4_HDRLEN sizeof(struct _Pflog4_hdr)
#define PFLOG4_HDRMIN sizeof(struct _Pflog4_hdr)

} // namespace

/*
 * Function: DecodePflog(Packet *, DAQ_PktHdr_t *, uint8_t *)
 *
 * Purpose: Pass pflog device packets off to IP or IP6 -fleck
 *
 * Arguments: p => pointer to the decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodePflog(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    uint8_t af, pflen;
    uint32_t hlen;
    uint32_t padlen = PFLOG_PADLEN;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)pkthdr->pktlen););

    /* do a little validation */
    if(cap_len < PFLOG2_HDRMIN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < minimum Pflog length! "
                    "(%d < %lu)\n", cap_len, (unsigned long)PFLOG2_HDRMIN);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the pf header structure over the packet data */
    switch(*((uint8_t*)pkt))
    {
        case PFLOG2_HDRMIN:
            p->pf2h = (Pflog2Hdr*)pkt;
            pflen = p->pf2h->length;
            hlen = PFLOG2_HDRLEN;
            af = p->pf2h->af;
            break;
        case PFLOG3_HDRMIN:
            p->pf3h = (Pflog3Hdr*)pkt;
            pflen = p->pf3h->length;
            hlen = PFLOG3_HDRLEN;
            af = p->pf3h->af;
            break;
        case PFLOG4_HDRMIN:
            p->pf4h = (Pflog4Hdr*)pkt;
            pflen = p->pf4h->length;
            hlen = PFLOG4_HDRLEN;
            af = p->pf4h->af;
            padlen = sizeof(p->pf4h->pad);
            break;
        default:
            if (ScLogVerbose())
            {
                ErrorMessage("unrecognized pflog header length! (%d)\n",
                    *((uint8_t*)pkt));
            }
            dc.discards++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    /* now that we know a little more, do a little more validation */
    if(cap_len < hlen)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < Pflog header length! "
                    "(%d < %d)\n", cap_len, hlen);
        }
        dc.discards++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }
    /* note that the pflen may exclude the padding which is always present */
    if(pflen < hlen - padlen || pflen > hlen)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Bad Pflog header length! (%d bytes)\n", pflen);
        }
        dc.discards++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP datagram size calculated to be "
                "%lu bytes\n", (unsigned long)(cap_len - hlen)););

    /* check the network type - should only be AF_INET or AF_INET6 */
    switch(af)
    {
        case AF_INET:   /* IPv4 */
            DecodeIP(p->pkt + hlen, cap_len - hlen, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

#if defined(AF_INET6)
        case AF_INET6:  /* IPv6 */
            DecodeIPV6(p->pkt + hlen, cap_len - hlen, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;
#endif

        default:
            /* To my knowledge, pflog devices can only
             * pass IP and IP6 packets. -fleck
             */
            // TBD add decoder drop event for unknown pflog network type
            dc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}
