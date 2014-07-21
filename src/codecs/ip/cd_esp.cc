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
// cd_esp.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "snort.h"
#include "codecs/ip/cd_esp_module.h"
#include "managers/packet_manager.h"
#include "codecs/codec_events.h"
#include "protocols/protocol_ids.h"

namespace
{

class EspCodec : public Codec
{
public:
    EspCodec() : Codec(CD_ESP_NAME){};
    ~EspCodec(){};


    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    
};


/* ESP constants */
const uint16_t ESP_PROT_ID = 50;
const uint32_t ESP_HEADER_LEN = 8;
const uint32_t ESP_AUTH_DATA_LEN = 12;
const uint32_t ESP_TRAILER_LEN = 2;

} // anonymous namespace



void EspCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ESP_PROT_ID);
}



/*
 * Function: DecodeESP(const uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Attempt to decode Encapsulated Security Payload.
 *          The contents are probably encrypted, but ESP is sometimes used
 *          with "null" encryption, solely for Authentication.
 *          This is more of a heuristic -- there is no ESP field that specifies
 *          the encryption type (or lack thereof).
 *
 * Arguments: pkt     => ptr to the packet data
 *            raw_len => length from here to the end of the packet
 *            p       => ptr to the Packet struct being filled out
 *
 * Returns: void function
 */
bool EspCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
    Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    const uint8_t *esp_payload;
    uint8_t pad_length;

    if (!ScESPDecoding())
        return false;
    

    /* The ESP header contains a crypto Initialization Vector (IV) and
       a sequence number. Skip these. */
    if (raw_len < (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN))
    {
        /* Truncated ESP traffic. Bail out here and inspect the rest as payload. */
        codec_events::decoder_event(p, DECODE_ESP_HEADER_TRUNC);
        p->data = raw_pkt;
        p->dsize = (uint16_t) raw_len;
        return false;
    }

    /* The Authentication Data at the end of the packet is variable-length.
       RFC 2406 says that Encryption and Authentication algorithms MUST NOT
       both be NULL, so we assume NULL Encryption and some other Authentication.

       The mandatory algorithms for Authentication are HMAC-MD5-96 and
       HMAC-SHA-1-96, so we assume a 12-byte authentication data at the end. */
    uint32_t guessed_len = raw_len - (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN);

    lyr_len = ESP_HEADER_LEN;
    esp_payload = raw_pkt + ESP_HEADER_LEN;
    pad_length = *(esp_payload + guessed_len);
    next_prot_id = *(esp_payload + guessed_len + 1);

    /* Adjust the packet length to account for the padding.
       If the padding length is too big, this is probably encrypted traffic. */
    if (pad_length < raw_len)
    {
        lyr_len += (pad_length);
    }
    else
    {
        p->packet_flags |= PKT_TRUST;
        lyr_len = ESP_HEADER_LEN;  // we want data to begin at (pkt + ESP_HEADER_LEN)
        next_prot_id = FINISHED_DECODE;
        return true;
    }



    if (!PacketManager::has_codec(next_prot_id))
    {
        /* Attempt to decode the inner payload.
           There is a small chance that an encrypted next_header would become a
           different valid next_header. The PKT_UNSURE_ENCAP flag tells the next
           decoder stage to silently ignore invalid headers. */
        p->packet_flags |= PKT_UNSURE_ENCAP;

        uint32_t* new_raw_len = const_cast<uint32_t*>(&raw_len);
        (*new_raw_len) = raw_len - (ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN);
        p->packet_flags |= PKT_ESP_LYR_PRESENT;
    }
    else
    {
        // If we cant' decode the packet anymore, this is probably encrypted.
        // set the data pointers and pretend this is an ip datagram.
        p->packet_flags |= PKT_TRUST;
        p->data = esp_payload;
        p->dsize = (u_short) raw_len - lyr_len;
    }

    return true;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new EspModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Codec* ctor(Module*)
{
    return new EspCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi esp_api =
{
    {
        PT_CODEC,
        CD_ESP_NAME,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor,
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};


const BaseApi* cd_esp = &esp_api.base;

