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

#include "decoder_includes.h"

class RpcFlowData : public FlowData
{
public:
    RpcFlowData();
    ~RpcFlowData();

    static void init()
    { flow_id = FlowData::get_flow_id(); };

public:
    static unsigned flow_id;
    RpcSsnData session;
};


class PppEncap : public Codec
{
public:
    PppEncap();
    ~PppEncap();

    static bool Decode(const uint8_t *, const DAQ_PktHdr_t*, 
        Packet *p, uint16_t &p_hdr_len, uint16_t &next_prot_id);

private:
    #define PPP_IP         0x0021        /* Internet Protocol */
    #define PPP_IPV6       0x0057        /* Internet Protocol v6 */
    #define PPP_VJ_COMP    0x002d        /* VJ compressed TCP/IP */
    #define PPP_VJ_UCOMP   0x002f        /* VJ uncompressed TCP/IP */
    #define PPP_IPX        0x002b        /* Novell IPX Protocol */

};




void DecodePppPktEncapsulated(const uint8_t *, const uint32_t, Packet *);



/*
 * Function: DecodePppPktEncapsulated(Packet *, const uint32_t len, uint8_t*)
 *
 * Purpose: Decode PPP traffic (RFC1661 framing).
 *
 * Arguments: p => pointer to decoded packet struct
 *            len => length of data to process
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
bool PppEncap::Decode(const uint8_t *pkt, uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, uint16_t &next_prot_id);
{
    static THREAD_LOCAL int had_vj = 0;
    uint16_t protocol;
    uint32_t hlen = 1; /* HEADER - try 1 then 2 */

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "PPP Packet!\n"););

#ifdef WORDS_MUSTALIGN
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet with PPP header.  "
                            "PPP is only 1 or 2 bytes and will throw off "
                            "alignment on this architecture when decoding IP, "
                            "causing a bus error - stop decoding packet.\n"););

    p->data = pkt;
    p->dsize = (uint16_t)len;
    return;
#endif  /* WORDS_MUSTALIGN */

    if (p->greh != NULL)
        dc.gre_ppp++;

    /* do a little validation:
     *
     */
    if(len < 2)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Length not big enough for even a single "
                         "header or a one byte payload\n");
        }
        return;
    }


    if(pkt[0] & 0x01)
    {
        /* Check for protocol compression rfc1661 section 5
         *
         */
        hlen = 1;
        protocol = pkt[0];
    }
    else
    {
        protocol = ntohs(*((uint16_t *)pkt));
        hlen = 2;
    }

    /*
     * We only handle uncompressed packets. Handling VJ compression would mean
     * to implement a PPP state machine.
     */
    switch (protocol)
    {
        case PPP_VJ_COMP:
            if (!had_vj)
                ErrorMessage("PPP link seems to use VJ compression, "
                        "cannot handle compressed packets!\n");
            had_vj = 1;
            return false;
        case PPP_VJ_UCOMP:
            /* VJ compression modifies the protocol field. It must be set
             * to tcp (only TCP packets can be VJ compressed) */
            if(len < (hlen + ipv4::ip_hdr_len()))
            {
                if (ScLogVerbose())
                    ErrorMessage("PPP VJ min packet length > captured len! "
                                 "(%d bytes)\n", len);
                return;
            }

            ((IPHdr *)(pkt + hlen))->ip_proto = IPPROTO_TCP;
            /* fall through */

        case PPP_IP:
//            PushLayer(PROTO_PPP_ENCAP, p, pkt, hlen);
            next_prot_id = ETHERNET_TYPE_IP;
//            DecodeIP(pkt + hlen, len - hlen, p);
            break;

        case PPP_IPV6:
//            PushLayer(PROTO_PPP_ENCAP, p, pkt, hlen);
            next_prot_id = ETHERNET_TYPE_IPV6;
//            DecodeIPV6(pkt + hlen, len - hlen, p);
            break;

#ifndef NO_NON_ETHER_DECODER
        case PPP_IPX:
//            PushLayer(PROTO_PPP_ENCAP, p, pkt, hlen);
            next_prot_id = ETHERNET_TYPE_IPX;
//            DecodeIPX(pkt + hlen, len - hlen, p);
            break;
#endif
    }
    p_hdr_len = hlen;
    return true;
}



static const char* name = "pppencap_decode";

static const CodecApi pppencap_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    {GRE_TYPE_PPP},  
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    NULL, // ctor
    NULL, // dtor
    PppEncap::Decode,
};


