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

#include "protocols/packet.h"  
#include "static_include.h"

#include "root_oldpflog.h"
#include "../decoder_includes.h"


/*
 * Function: DecodeOldPflog(Packet *, DAQ_PktHdr_t *, uint8_t *)
 *
 * Purpose: Pass old pflog format device packets off to IP or IP6 -fleck
 *
 * Arguments: p => pointer to the decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodeOldPflog(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    MODULE_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)pkthdr->pktlen););

    /* do a little validation */
    if(cap_len < PFLOG1_HDRLEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < Pflog header length "
                    "(%d bytes)\n", cap_len);
        }
        MODULE_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the pf header structure over the packet data */
    p->pf1h = (Pflog1Hdr*)pkt;

    /*  get the network type - should only be AF_INET or AF_INET6 */
    switch(ntohl(p->pf1h->af))
    {
        case AF_INET:   /* IPv4 */
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP datagram size calculated to be %lu "
                        "bytes\n", (unsigned long)(cap_len - PFLOG1_HDRLEN)););

            DecodeIP(p->pkt + PFLOG1_HDRLEN, cap_len - PFLOG1_HDRLEN, p);
            MODULE_PROFILE_END(decodePerfStats);
            return;

#if defined(AF_INET6)
        case AF_INET6:  /* IPv6 */
            DecodeIPV6(p->pkt + PFLOG1_HDRLEN, cap_len - PFLOG1_HDRLEN, p);
            MODULE_PROFILE_END(decodePerfStats);
            return;
#endif

        default:
            /* To my knowledge, pflog devices can only
             * pass IP and IP6 packets. -fleck
             */
            // TBD add decoder drop event for unknown old pflog network type
            dc.other++;
            MODULE_PROFILE_END(decodePerfStats);
            return;
    }

    MODULE_PROFILE_END(decodePerfStats);
    return;
}

