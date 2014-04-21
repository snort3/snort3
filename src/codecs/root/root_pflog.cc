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
#include "decode.h"  
#include "static_include.h"

#include "root_pflog.h"
#include "../decoder_includes.h"


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
