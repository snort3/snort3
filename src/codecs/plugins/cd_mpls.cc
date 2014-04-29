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
** You should have received a copy of the GNU General Public LicenseUpdateMPLSStats
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// cd_mpls.cc author Josh Rosenbaum <jorosenba@cisco.com>



#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "network_inspectors/perf_monitor/perf_base.h"
#include "network_inspectors/perf_monitor/perf.h"
#include "snort.h"
#include "protocols/mpls.h"
#include "protocols/undefined_protocols.h"
#include "events/codec_events.h"
#include "packet_io/active.h"
#include "protocols/ethertypes.h"
#include "protocols/mpls.h"

namespace
{

class MplsCodec : public Codec
{
public:
    MplsCodec() : Codec("MPLS"){};
    ~MplsCodec(){};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, int &next_prot_id);    

    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_MPLS; };
};


const uint16_t ETHERNET_TYPE_MPLS_UNICAST = 0x8847;
const uint16_t ETHERNET_TYPE_MPLS_MULTICAST = 0x8848;

const static uint32_t MPLS_HEADER_LEN = 4;
const static uint32_t NUM_RESERVED_LABELS = 16;

} // namespace

static int checkMplsHdr(uint32_t, uint8_t, uint8_t, uint8_t, Packet *);


bool MplsCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, int &next_prot_id)
{
    uint32_t* tmpMplsHdr;
    uint32_t mpls_h;
    uint32_t label;
    lyr_len= 0;

    uint8_t exp;
    uint8_t bos = 0;
    uint8_t ttl;
    uint8_t chainLen = 0;
    uint32_t stack_len = len;

    int iRet = 0;

//    dc.mpls++;
    UpdateMPLSStats(&sfBase, len, Active_PacketWasDropped());
    tmpMplsHdr = (uint32_t *) raw_pkt;
    p->mpls = NULL;

    while (!bos)
    {
        if(stack_len < MPLS_HEADER_LEN)
        {
            codec_events::decoder_event(p, DECODE_BAD_MPLS);

//            dc.discards++;
            p->iph = NULL;
            p->family = NO_IP;
            return false;
        }

        mpls_h  = ntohl(*tmpMplsHdr);
        ttl = (uint8_t)(mpls_h & 0x000000FF);
        mpls_h = mpls_h>>8;
        bos = (uint8_t)(mpls_h & 0x00000001);
        exp = (uint8_t)(mpls_h & 0x0000000E);
        label = (mpls_h>>4) & 0x000FFFFF;

        if((label<NUM_RESERVED_LABELS)&&((iRet = checkMplsHdr(label, exp, bos, ttl, p)) < 0))
            return false;

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
            codec_events::decoder_event(p, DECODE_MPLS_LABEL_STACK);

//            dc.discards++;
            p->iph = NULL;
            p->family = NO_IP;
            return false;
        }
    }   /* while bos not 1, peel off more labels */

    lyr_len = (uint8_t*)tmpMplsHdr - raw_pkt;

    switch (iRet)
    {
        case MPLS_PAYLOADTYPE_IPV4:
            next_prot_id = ETHERTYPE_IPV4;
            break;

        case MPLS_PAYLOADTYPE_IPV6:
            next_prot_id = ETHERTYPE_IPV6;
            break;

        case MPLS_PAYLOADTYPE_ETHERNET:
            next_prot_id = ETHERTYPE_TRANS_ETHER_BRIDGING;
            break;

        default:
            next_prot_id = -1;
            break;
    }

    return true;
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
                            codec_events::decoder_event(p, DECODE_BAD_MPLS_LABEL0);
                        else
                            codec_events::decoder_event(p, DECODE_BAD_MPLS_LABEL2);
                   }
                   break;
               }

#if 0
               /* This is valid per RFC 4182.  Just pop this label off, ignore it
                * and move on to the next one.
                */
               if( !label )
                   codec_events::decoder_event(p, DECODE_BAD_MPLS_LABEL0);
               else
                   codec_events::decoder_event(p, DECODE_BAD_MPLS_LABEL2);

               dc.discards++;
               p->iph = NULL;
               p->family = NO_IP;
               return(-1);
#endif
               break;
        case 1:
               if(!bos) break;

               codec_events::decoder_event(p, DECODE_BAD_MPLS_LABEL1);

//               dc.discards++;
               p->iph = NULL;
               p->family = NO_IP;
               iRet = MPLS_PAYLOADTYPE_ERROR;
               break;

      case 3:
               codec_events::decoder_event(p, DECODE_BAD_MPLS_LABEL3);

//               dc.discards++;
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
                codec_events::decoder_event(p, DECODE_MPLS_RESERVED_LABEL);
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


static void get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERNET_TYPE_MPLS_UNICAST);
    v.push_back(ETHERNET_TYPE_MPLS_MULTICAST);
}

static Codec* ctor()
{
    return new MplsCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "mpls_codec";
static const CodecApi mpls_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    nullptr, // get_dlt
    get_protocol_ids,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &mpls_api.base,
    nullptr
};
#else
const BaseApi* cd_mpls = &mpls_api.base;
#endif





