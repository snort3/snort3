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


#include "codec.h"
#include "protocols/gtp.h"



namespace
{

class GtpCodec : public Codec
{
public:
    GtpCodec() : Codec("gtp"){};
    ~GtpCodec();


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &p_hdr_len, int &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual void get_data_link_type(std::vector<int>&){};
    
};

} // anonymous namespace



/* Function: DecodeGTP(uint8_t *, uint32_t, Packet *)
 *
 * GTP (GPRS Tunneling Protocol) is layered over UDP.
 * Decode these (if present) and go to DecodeIPv6/DecodeIP.
 *
 */

void DecodeGTP(const uint8_t *pkt, uint32_t len, Packet *p)
{
    uint32_t header_len;
    uint8_t  next_hdr_type;
    uint8_t  version;
    uint8_t  ip_ver;
    GTPHdr *hdr;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Start GTP decoding.\n"););

    hdr = (GTPHdr *) pkt;

    if (p->GTPencapsulated)
    {
        DecoderAlertEncapsulated(p, DECODE_GTP_MULTIPLE_ENCAPSULATION,
                DECODE_GTP_MULTIPLE_ENCAPSULATION_STR,
                pkt, len);
        return;
    }
    else
    {
        p->GTPencapsulated = 1;
    }
    /*Check the length*/
    if (len < GTP_MIN_LEN)
       return;
    /* We only care about PDU*/
    if ( hdr->type != 255)
       return;
    /*Check whether this is GTP or GTP', Exit if GTP'*/
    if (!(hdr->flag & 0x10))
       return;

    /*The first 3 bits are version number*/
    version = (hdr->flag & 0xE0) >> 5;
    switch (version)
    {
    case 0: /*GTP v0*/
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "GTP v0 packets.\n"););

        header_len = GTP_V0_HEADER_LEN;
        /*Check header fields*/
        if (len < header_len)
        {
            DecoderEvent(p, EVARGS(GTP_BAD_LEN));
            return;
        }

        p->proto_bits |= PROTO_BIT__GTP;

        /*Check the length field. */
        if (len != ((unsigned int)ntohs(hdr->length) + header_len))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Calculated length %d != %d in header.\n",
                    len - header_len, ntohs(hdr->length)););
            DecoderEvent(p, EVARGS(GTP_BAD_LEN));
            return;
        }

        break;
    case 1: /*GTP v1*/
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "GTP v1 packets.\n"););

        /*Check the length based on optional fields and extension header*/
        if (hdr->flag & 0x07)
        {

            header_len = GTP_V1_HEADER_LEN;

            /*Check optional fields*/
            if (len < header_len)
            {
                DecoderEvent(p, EVARGS(GTP_BAD_LEN));
                return;
            }
            next_hdr_type = *(pkt + header_len - 1);

            /*Check extension headers*/
            while (next_hdr_type)
            {
                uint16_t ext_hdr_len;
                /*check length before reading data*/
                if (len < header_len + 4)
                {
                    DecoderEvent(p, EVARGS(GTP_BAD_LEN));
                    return;
                }

                ext_hdr_len = *(pkt + header_len);

                if (!ext_hdr_len)
                {
                    DecoderEvent(p, EVARGS(GTP_BAD_LEN));
                    return;
                }
                /*Extension header length is a unit of 4 octets*/
                header_len += ext_hdr_len * 4;

                /*check length before reading data*/
                if (len < header_len)
                {
                    DecoderEvent(p, EVARGS(GTP_BAD_LEN));
                    return;
                }
                next_hdr_type = *(pkt + header_len - 1);
            }
        }
        else
            header_len = GTP_MIN_LEN;

        p->proto_bits |= PROTO_BIT__GTP;

        /*Check the length field. */
        if (len != ((unsigned int)ntohs(hdr->length) + GTP_MIN_LEN))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Calculated length %d != %d in header.\n",
                    len - GTP_MIN_LEN, ntohs(hdr->length)););
            DecoderEvent(p, EVARGS(GTP_BAD_LEN));
            return;
        }

        break;
    default:
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown protocol version.\n"););
        return;

    }

//    PushLayer(PROTO_GTP, p, pkt, header_len);

    if ( ScTunnelBypassEnabled(TUNNEL_GTP) )
        Active_SetTunnelBypass();

    len -=  header_len;
    if (len > 0)
    {
        ip_ver = *(pkt+header_len) & 0xF0;
        if (ip_ver == 0x40)
            DecodeIP(pkt+header_len, len, p);
        else if (ip_ver == 0x60)
            DecodeIPV6(pkt+header_len, len, p);
        p->packet_flags &= ~PKT_UNSURE_ENCAP;
    }
}


#if 0

/*
 * ENCODERS
 */
 
static EncStatus update_GTP_length(GTPHdr* h, int gtp_total_len )
{
    /*The first 3 bits are version number*/
    uint8_t version = (h->flag & 0xE0) >> 5;
    switch (version)
    {
    case 0: /*GTP v0*/
        h->length = htons((uint16_t)(gtp_total_len - GTP_V0_HEADER_LEN));
        break;
    case 1: /*GTP v1*/
        h->length = htons((uint16_t)(gtp_total_len - GTP_MIN_LEN));
        break;
    default:
        return EncStatus::ENC_BAD_PROTO;
    }
    return EncStatus::ENC_OK;

}

EncStatus GTP_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int n = enc->p->layers[enc->layer-1].length;
    int len;

    GTPHdr* hi = (GTPHdr*) (enc->p->layers[enc->layer-1].start);
    GTPHdr* ho = (GTPHdr*)(out->base + out->end);
    uint32_t start = out->end;
    PROTO_ID next = NextEncoder(enc);

    UPDATE_BOUND(out, n);
    memcpy(ho, hi, n);

    if ( next < PROTO_MAX )
    {
        EncStatus err = encoders[next].fencode(enc, in, out);
        if (EncStatus::ENC_OK != err ) return err;
    }
    len = out->end - start;
    return( update_GTP_length(ho,len));
}

EncStatus GTP_Update (Packet*, Layer* lyr, uint32_t* len)
{
    GTPHdr* h = (GTPHdr*)(lyr->start);
    *len += lyr->length;
    return( update_GTP_length(h,*len));
}

}

#endif

void NameCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(gtp::get_id());
}

static Codec* ctor()
{
    return new GtpCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "gtp_codec";

static const CodecApi ipv6_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
};
