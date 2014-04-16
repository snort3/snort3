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

#include "network_inspectors/perfmonitor/perf.h"
#include  "network_inspectors/perfmonitor/perf_base.h"

#include "prot_mpls.h"
#include "prot_ipv6.h"
#include "prot_ipv4.h"
#include "prot_ethloopback.h"
#include "prot_ethovermpls.h"

static int checkMplsHdr(uint32_t, uint8_t, uint8_t, uint8_t, Packet *);

void DecodeMPLS(const uint8_t* pkt, const uint32_t len, Packet* p)
{
    uint32_t* tmpMplsHdr;
    uint32_t mpls_h;
    uint32_t label;
    uint32_t mlen = 0;

    uint8_t exp;
    uint8_t bos = 0;
    uint8_t ttl;
    uint8_t chainLen = 0;
    uint32_t stack_len = len;

    int iRet = 0;


    if(!ScMplsMulticast())
    {
        DecoderEvent(p, DECODE_BAD_MPLS,
                        DECODE_MULTICAST_MPLS_STR);
//        SnortEventqAdd(GENERATOR_SNORT_DECODE, DECODE_BAD_MPLS, 1, DECODE_CLASS, 3, DECODE_MULTICAST_MPLS_STR, 0);
    }


    dc.mpls++;
    UpdateMPLSStats(&sfBase, len, Active_PacketWasDropped());
    tmpMplsHdr = (uint32_t *) pkt;
    p->mpls = NULL;

    while (!bos)
    {
        if(stack_len < MPLS_HEADER_LEN)
        {
            DecoderEvent(p, DECODE_BAD_MPLS, DECODE_BAD_MPLS_STR);

            dc.discards++;
            p->iph = NULL;
            p->family = NO_IP;
            return;
        }

        mpls_h  = ntohl(*tmpMplsHdr);
        ttl = (uint8_t)(mpls_h & 0x000000FF);
        mpls_h = mpls_h>>8;
        bos = (uint8_t)(mpls_h & 0x00000001);
        exp = (uint8_t)(mpls_h & 0x0000000E);
        label = (mpls_h>>4) & 0x000FFFFF;

        if((label<NUM_RESERVED_LABELS)&&((iRet = checkMplsHdr(label, exp, bos, ttl, p)) < 0))
            return;

        if( bos )
        {
            p->mplsHdr.label = label;
            p->mplsHdr.exp = exp;
            p->mplsHdr.bos = bos;
            p->mplsHdr.ttl = ttl;
            /**
            p->mpls = &(p->mplsHdr);
			**/
            p->mpls = tmpMplsHdr;
            if(!iRet)
            {
                iRet = ScMplsPayloadType();
            }
        }
        tmpMplsHdr++;
        stack_len -= MPLS_HEADER_LEN;

        if ((ScMplsStackDepth() != -1) && (chainLen++ >= ScMplsStackDepth()))
        {
            DecoderEvent(p, DECODE_MPLS_LABEL_STACK,
                            DECODE_MPLS_LABEL_STACK_STR);

            dc.discards++;
            p->iph = NULL;
            p->family = NO_IP;
            return;
        }
    }   /* while bos not 1, peel off more labels */

    mlen = (uint8_t*)tmpMplsHdr - pkt;
    PushLayer(PROTO_MPLS, p, pkt, mlen);
    mlen = len - mlen;

    switch (iRet)
    {
        case MPLS_PAYLOADTYPE_IPV4:
            DecodeIP((uint8_t *)tmpMplsHdr, mlen, p);
            break;

        case MPLS_PAYLOADTYPE_IPV6:
            DecodeIPV6((uint8_t *)tmpMplsHdr, mlen, p);
            break;

        case MPLS_PAYLOADTYPE_ETHERNET:
            DecodeEthOverMPLS((uint8_t *)tmpMplsHdr, mlen, p);
            break;

        default:
            break;
    }
    return;
}


/*
 * check if reserved labels are used properly
 */
static int checkMplsHdr(
    uint32_t label, uint8_t, uint8_t bos, uint8_t, Packet *p)
{
    int iRet = 0;
    switch(label)
    {
        case 0:
        case 2:
               /* check if this label is the bottom of the stack */
               if(bos)
               {
                   if ( label == 0 )
                       iRet = MPLS_PAYLOADTYPE_IPV4;
                   else if ( label == 2 )
                       iRet = MPLS_PAYLOADTYPE_IPV6;


                   /* when label == 2, IPv6 is expected;
                    * when label == 0, IPv4 is expected */
                   if((label&&(ScMplsPayloadType() != MPLS_PAYLOADTYPE_IPV6))
                       ||((!label)&&(ScMplsPayloadType() != MPLS_PAYLOADTYPE_IPV4)))
                   {
                        if( !label )
                            DecoderEvent(p, DECODE_BAD_MPLS_LABEL0,
                                            DECODE_BAD_MPLS_LABEL0_STR);
                        else
                            DecoderEvent(p, DECODE_BAD_MPLS_LABEL2,
                                            DECODE_BAD_MPLS_LABEL2_STR);
                   }
                   break;
               }

#if 0
               /* This is valid per RFC 4182.  Just pop this label off, ignore it
                * and move on to the next one.
                */
               if( !label )
                   DecoderEvent(p, DECODE_BAD_MPLS_LABEL0,
                                   DECODE_BAD_MPLS_LABEL0_STR);
               else
                   DecoderEvent(p, DECODE_BAD_MPLS_LABEL2,
                                   DECODE_BAD_MPLS_LABEL2_STR);

               dc.discards++;
               p->iph = NULL;
               p->family = NO_IP;
               return(-1);
#endif
               break;
        case 1:
               if(!bos) break;

       	       DecoderEvent(p, DECODE_BAD_MPLS_LABEL1,
                               DECODE_BAD_MPLS_LABEL1_STR);

               dc.discards++;
               p->iph = NULL;
               p->family = NO_IP;
               iRet = MPLS_PAYLOADTYPE_ERROR;
               break;

	    case 3:
               DecoderEvent(p, DECODE_BAD_MPLS_LABEL3,
                               DECODE_BAD_MPLS_LABEL3_STR);

               dc.discards++;
               p->iph = NULL;
               p->family = NO_IP;
               iRet = MPLS_PAYLOADTYPE_ERROR;
               break;
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
                DecoderEvent(p, DECODE_MPLS_RESERVED_LABEL,
                                DECODE_MPLS_RESERVEDLABEL_STR);
                break;
        default:
                break;
    }
    if ( !iRet )
    {
        iRet = ScMplsPayloadType();
    }
    return iRet;
}


static const char* name = "mpls_decode";

static const CodecApi mpls_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    {ETHERNET_TYPE_MPLS_UNICAST, ETHERNET_TYPE_MPLS_MULTICAST},  
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    NULL, // ctor
    NULL, // dtor
    ErspanType2::DecodeTCP,
};



