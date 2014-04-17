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
#if 0

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif
#endif

#include "framework/codec.h"
#include "codecs/codec_events.h"


namespace
{

class EspCodec : public Codec
{
public:
    EspCodec() : Codec("ESP"){};
    ~EspCodec();


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &p_hdr_len, int &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual void get_data_link_type(std::vector<int>&){};
    
};

} // anonymous namespace







/*
 * Function: DecodeESP(const uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Attempt to decode Encapsulated Security Payload.
 *          The contents are probably encrypted, but ESP is sometimes used
 *          with "null" encryption, solely for Authentication.
 *          This is more of a heuristic -- there is no ESP field that specifies
 *          the encryption type (or lack thereof).
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => ptr to the Packet struct being filled out
 *
 * Returns: void function
 */
virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
    Packet *, uint16_t &p_hdr_len, int &next_prot_id)
{
    const uint8_t *esp_payload;
    uint8_t next_header;
    uint8_t pad_length;
    uint8_t save_layer = p->next_layer;

    if (!ScESPDecoding())
        return false;
    

    /* The ESP header contains a crypto Initialization Vector (IV) and
       a sequence number. Skip these. */
    if (len < (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN))
    {
        /* Truncated ESP traffic. Bail out here and inspect the rest as payload. */
        DecoderEvent(p, DECODE_ESP_HEADER_TRUNC);
        p->data = pkt;
        p->dsize = (uint16_t) len;
        return;
    }
    esp_payload = pkt + ESP_HEADER_LEN;

    /* The Authentication Data at the end of the packet is variable-length.
       RFC 2406 says that Encryption and Authentication algorithms MUST NOT
       both be NULL, so we assume NULL Encryption and some other Authentication.

       The mandatory algorithms for Authentication are HMAC-MD5-96 and
       HMAC-SHA-1-96, so we assume a 12-byte authentication data at the end. */
    len -= (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN);

    pad_length = *(esp_payload + len);
    next_header = *(esp_payload + len + 1);

    /* Adjust the packet length to account for the padding.
       If the padding length is too big, this is probably encrypted traffic. */
    if (pad_length < len)
    {
        len -= (pad_length);
    }
    else
    {
        p->packet_flags |= PKT_TRUST;
        p->data = esp_payload;
        p->dsize = (u_short) len;
        return;
    }

    /* Attempt to decode the inner payload.
       There is a small chance that an encrypted next_header would become a
       different valid next_header. The PKT_UNSURE_ENCAP flag tells the next
       decoder stage to silently ignore invalid headers. */

    p->packet_flags |= PKT_UNSURE_ENCAP;
    switch (next_header)
    {
       case IPPROTO_IPIP:
            DecodeIP(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        case IPPROTO_IPV6:
            DecodeIPV6(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

       case IPPROTO_TCP:
            dc.tcp++;
            DecodeTCP(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        case IPPROTO_UDP:
            dc.udp++;
            DecodeUDP(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        case IPPROTO_ICMP:
            dc.icmp++;
            DecodeICMP(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        case IPPROTO_GRE:
            dc.gre++;
            DecodeGRE(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        default:
            /* If we didn't get a valid next_header, this packet is probably
               encrypted. Start data here and treat it as an IP datagram. */
            p->data = esp_payload;
            p->dsize = (u_short) len;
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            p->packet_flags |= PKT_TRUST;
            return;
    }

    /* If no protocol was added to the stack, than we assume its'
     * encrypted. */
    if (save_layer == p->next_layer)
        p->packet_flags |= PKT_TRUST;
}


void EspCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ESP);
}

static Codec* ctor()
{
    return new EspCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}




static const char* name = "esp_decode";

static const CodecApi esp_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    NULL, // ctor
    NULL, // dtor
};

