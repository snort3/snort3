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

#include "root_slip.h"
#include "../decoder_includes.h"



/*
 * Function: DecodeSlipPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode SLIP traffic
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeSlipPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    /* do a little validation */
    if(cap_len < SLIP_HEADER_LEN)
    {
        ErrorMessage("SLIP header length < captured len! (%d bytes)\n",
                     cap_len);
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    DecodeIP(p->pkt + SLIP_HEADER_LEN, cap_len - SLIP_HEADER_LEN, p);
    PREPROC_PROFILE_END(decodePerfStats);
}

