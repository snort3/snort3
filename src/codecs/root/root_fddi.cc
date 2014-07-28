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

#include "../decoder_includes.h"


anonymous
{

/* FDDI header is always this: -worm5er */
struct Fddi_hdr
{
    uint8_t fc;        /* frame control field */
    uint8_t daddr[FDDI_ALEN];  /* src address */
    uint8_t saddr[FDDI_ALEN];  /* dst address */
}         Fddi_hdr;

/* splitting the llc up because of variable lengths of the LLC -worm5er */
struct Fddi_llc_saps
{
    uint8_t dsap;
    uint8_t ssap;
}              Fddi_llc_saps;

/* I've found sna frames have two addition bytes after the llc saps -worm5er */
struct Fddi_llc_sna
{
    uint8_t ctrl_fld[2];
}             Fddi_llc_sna;

/* I've also found other frames that seem to have only one byte...  We're only
really intersted in the IP data so, until we want other, I'm going to say
the data is one byte beyond this frame...  -worm5er */
struct Fddi_llc_other
{
    uint8_t ctrl_fld[1];
}               Fddi_llc_other;

/* Just like TR the ip/arp data is setup as such: -worm5er */
struct Fddi_llc_iparp
{
    uint8_t ctrl_fld;
    uint8_t protid[3];
    uint16_t ethertype;
}               Fddi_llc_iparp;

} // anonymous

/*
 * Function: DecodeFDDIPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Mainly taken from CyberPsycotic's Token Ring Code -worm5er
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeFDDIPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    uint32_t dataoff = sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps);



    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long) cap_len,(unsigned long) pkthdr->pktlen);
            );

    /* Bounds checking (might not be right yet -worm5er) */
    if(cap_len < dataoff)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < FDDI header length! "
                         "(%d %d bytes)\n", cap_len, dataoff);
            MODULE_PROFILE_END(decodePerfStats);
            return;
        }
    }
    /* let's put this in as the fddi header structure */
    p->fddihdr = (Fddi_hdr *) pkt;

    p->fddisaps = (Fddi_llc_saps *) (pkt + sizeof(Fddi_hdr));

    /* First we'll check and see if it's an IP/ARP Packet... */
    /* Then we check to see if it's a SNA packet */
    /*
     * Lastly we'll declare it none of the above and just slap something
     * generic on it to discard it with (I know that sucks, but heck we're
     * only looking for IP/ARP type packets currently...  -worm5er
     */
    if((p->fddisaps->dsap == FDDI_DSAP_IP) && (p->fddisaps->ssap == FDDI_SSAP_IP))
    {
        dataoff += sizeof(Fddi_llc_iparp);

        if(cap_len < dataoff)
        {
            if (ScLogVerbose())
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", cap_len, dataoff);
                MODULE_PROFILE_END(decodePerfStats);
                return;
            }
        }

        p->fddiiparp = (Fddi_llc_iparp *) (pkt + sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps));
    }
    else if((p->fddisaps->dsap == FDDI_DSAP_SNA) &&
            (p->fddisaps->ssap == FDDI_SSAP_SNA))
    {
        dataoff += sizeof(Fddi_llc_sna);

        if(cap_len < dataoff)
        {
            if (ScLogVerbose())
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", cap_len, dataoff);
                MODULE_PROFILE_END(decodePerfStats);
                return;
            }
        }

        p->fddisna = (Fddi_llc_sna *) (pkt + sizeof(Fddi_hdr) +
                                       sizeof(Fddi_llc_saps));
    }
    else
    {
        dataoff += sizeof(Fddi_llc_other);
        p->fddiother = (Fddi_llc_other *) (pkt + sizeof(Fddi_hdr) +
                sizeof(Fddi_llc_other));

        if(cap_len < dataoff)
        {
            if (ScLogVerbose())
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", cap_len, dataoff);
                MODULE_PROFILE_END(decodePerfStats);
                return;
            }
        }
    }

    /*
     * Now let's see if we actually care about the packet... If we don't,
     * throw it out!!!
     */
    if((p->fddisaps->dsap != FDDI_DSAP_IP) || (p->fddisaps->ssap != FDDI_SSAP_IP))
    {
        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE,
                    "This FDDI Packet isn't an IP/ARP packet...\n");
                );
        MODULE_PROFILE_END(decodePerfStats);
        return;
    }

    cap_len -= dataoff;

    switch(htons(p->fddiiparp->ethertype))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding IP\n"););
            DecodeIP(p->pkt + dataoff, cap_len, p);
            MODULE_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding ARP\n"););
            dc.arp++;

            MODULE_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + dataoff, cap_len, p);
            MODULE_PROFILE_END(decodePerfStats);
            return;


        default:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown network protocol: %d\n",
                        htons(p->fddiiparp->ethertype));
                    );
            // TBD add decoder drop event for unknown fddi/eth type
            dc.other++;

            MODULE_PROFILE_END(decodePerfStats);
            return;
    }

    MODULE_PROFILE_END(decodePerfStats);
    return;
}

