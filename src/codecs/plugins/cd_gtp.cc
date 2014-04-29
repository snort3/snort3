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
// cd_gtp.cc author Josh Rosenbaum <jorosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_debug.h"
#include "codec.h"
#include "protocols/gtp.h"
#include "codecs/decode_module.h"
#include "packet.h"
#include "events/codec_events.h"
#include "snort.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "packet_io/active.h"

#include "protocols/undefined_protocols.h"

namespace
{

class GtpCodec : public Codec
{
public:
    GtpCodec() : Codec("GTP"){};
    ~GtpCodec(){};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, int &next_prot_id);


    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_GTP; };    
};

} // anonymous namespace



/* Function: DecodeGTP(uint8_t *, uint32_t, Packet *)
 *
 * GTP (GPRS Tunneling Protocol) is layered over UDP.
 * Decode these (if present) and go to DecodeIPv6/DecodeIP.
 *
 */

bool GtpCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
    Packet *p, uint16_t &lyr_len, int &next_prot_id)
{
    uint32_t header_len;
    uint8_t  next_hdr_type;
    uint8_t  version;
    uint8_t  ip_ver;
    GTPHdr *hdr;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Start GTP decoding.\n"););

    hdr = (GTPHdr *) raw_pkt;

    if (p->GTPencapsulated)
    {
        codec_events::decoder_alert_encapsulated(p, DECODE_GTP_MULTIPLE_ENCAPSULATION,
                raw_pkt, len);
        return false;
    }
    else
    {
        p->GTPencapsulated = 1;
    }
    /*Check the length*/
    if (len < gtp::min_hdr_len())
       return false;
    /* We only care about PDU*/
    if ( hdr->type != 255)
       return false;
    /*Check whether this is GTP or GTP', Exit if GTP'*/
    if (!(hdr->flag & 0x10))
       return false;

    /*The first 3 bits are version number*/
    version = (hdr->flag & 0xE0) >> 5;
    switch (version)
    {
    case 0: /*GTP v0*/
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "GTP v0 packets.\n"););

        lyr_len = gtp::v0_hdr_len();
        /*Check header fields*/
        if (len < lyr_len)
        {
            codec_events::decoder_event(p, DECODE_GTP_BAD_LEN);
            return false;
        }

        p->proto_bits |= PROTO_BIT__GTP;

        /*Check the length field. */
        if (len != ((unsigned int)ntohs(hdr->length) + lyr_len))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Calculated length %d != %d in header.\n",
                    len - lyr_len, ntohs(hdr->length)););
            codec_events::decoder_event(p, DECODE_GTP_BAD_LEN);
            return false;
        }

        break;
    case 1: /*GTP v1*/
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "GTP v1 packets.\n"););

        /*Check the length based on optional fields and extension header*/
        if (hdr->flag & 0x07)
        {

            lyr_len =  gtp::v1_hdr_len();

            /*Check optional fields*/
            if (len < lyr_len)
            {
                codec_events::decoder_event(p, DECODE_GTP_BAD_LEN);
                return false;
            }
            next_hdr_type = *(raw_pkt + lyr_len - 1);

            /*Check extension headers*/
            while (next_hdr_type)
            {
                uint16_t ext_hdr_len;
                /*check length before reading data*/
                if (len < lyr_len + 4)
                {
                    codec_events::decoder_event(p, DECODE_GTP_BAD_LEN);
                    return false;
                }

                ext_hdr_len = *(raw_pkt + lyr_len);

                if (!ext_hdr_len)
                {
                    codec_events::decoder_event(p, DECODE_GTP_BAD_LEN);
                    return false;
                }
                /*Extension header length is a unit of 4 octets*/
                lyr_len += ext_hdr_len * 4;

                /*check length before reading data*/
                if (len < lyr_len)
                {
                    codec_events::decoder_event(p, DECODE_GTP_BAD_LEN);
                    return false;
                }
                next_hdr_type = *(raw_pkt + lyr_len - 1);
            }
        }
        else
            lyr_len = gtp::min_hdr_len();

        p->proto_bits |= PROTO_BIT__GTP;

        /*Check the length field. */
        if (len != ((unsigned int)ntohs(hdr->length) + gtp::min_hdr_len()))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Calculated length %d != %d in header.\n",
                    len - gtp::min_hdr_len(), ntohs(hdr->length)););
            codec_events::decoder_event(p, DECODE_GTP_BAD_LEN);
            return false;
        }

        break;
    default:
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown protocol version.\n"););
        return false;

    }

    if ( ScTunnelBypassEnabled(TUNNEL_GTP) )
        Active_SetTunnelBypass();


    if (len > 0)
    {
        p->packet_flags |= PKT_UNSURE_ENCAP;

        ip_ver = *(raw_pkt + gtp::min_hdr_len()) & 0xF0;
        if (ip_ver == 0x40)
            next_prot_id = ipv4::prot_id(); 
        else if (ip_ver == 0x60)
            next_prot_id = ipv6::prot_id();
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

static void get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(PROTOCOL_GTP);
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
static const CodecApi gtp_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    NULL,
    get_protocol_ids,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &gtp_api.base,
    nullptr
};
#else
const BaseApi* cd_gtp = &gtp_api.base;
#endif

