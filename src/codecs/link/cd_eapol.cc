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

#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"


namespace
{

class EapolCodec : public Codec
{
public:
    EapolCodec() : Codec("eapol"){};
    ~EapolCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    
};

static const uint16_t ETHERTYPE_EAPOL = 0x888e;


#ifndef NO_NON_ETHER_DECODER

/* IEEE 802.1x eapol types */
#define EAPOL_TYPE_EAP      0x00      /* EAP packet */
#define EAPOL_TYPE_START    0x01      /* EAPOL start */
#define EAPOL_TYPE_LOGOFF   0x02      /* EAPOL Logoff */
#define EAPOL_TYPE_KEY      0x03      /* EAPOL Key */
#define EAPOL_TYPE_ASF      0x04      /* EAPOL Encapsulated ASF-Alert */


#endif // NO_NON_ETHER_DECODER


/* Extensible Authentication Protocol Codes RFC 2284*/
#define EAP_CODE_REQUEST    0x01
#define EAP_CODE_RESPONSE   0x02
#define EAP_CODE_SUCCESS    0x03
#define EAP_CODE_FAILURE    0x04
/* EAP Types */
#define EAP_TYPE_IDENTITY   0x01
#define EAP_TYPE_NOTIFY     0x02
#define EAP_TYPE_NAK        0x03
#define EAP_TYPE_MD5        0x04
#define EAP_TYPE_OTP        0x05
#define EAP_TYPE_GTC        0x06
#define EAP_TYPE_TLS        0x0d



/* Extensible Authentication Protocol Codes RFC 2284*/
#define EAP_CODE_REQUEST    0x01
#define EAP_CODE_RESPONSE   0x02
#define EAP_CODE_SUCCESS    0x03
#define EAP_CODE_FAILURE    0x04
/* EAP Types */
#define EAP_TYPE_IDENTITY   0x01
#define EAP_TYPE_NOTIFY     0x02
#define EAP_TYPE_NAK        0x03
#define EAP_TYPE_MD5        0x04
#define EAP_TYPE_OTP        0x05
#define EAP_TYPE_GTC        0x06
#define EAP_TYPE_TLS        0x0d



} // namespace

/*************************************************
 ***************  private codecs  ****************
 *************************************************/

/*
 * Function: DecodeEAP(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Extensible Authentication Protocol
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEAP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    p->eaph = (EAPHdr *) pkt;
    if(len < sizeof(EAPHdr))
    {
        codec_events::decoder_event(p, DECODE_EAP_TRUNCATED);
        return;
    }
    if (p->eaph->code == EAP_CODE_REQUEST ||
            p->eaph->code == EAP_CODE_RESPONSE) {
        p->eaptype = pkt + sizeof(EAPHdr);
    }
    return;
}


/*
 * Function: DecodeEapolKey(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode 1x key setup
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEapolKey(const uint8_t * pkt, uint32_t len, Packet * p)
{
    p->eapolk = (EapolKey *) pkt;
    if(len < sizeof(EapolKey))
    {
        codec_events::decoder_event(p, DECODE_EAPKEY_TRUNCATED);
    }

    return;
}


/*************************************************
 ************** main codec functions  ************
 *************************************************/

bool EapolCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t & /*lyr_len*/, uint16_t &/*next_prot_id */)
{
    p->eplh = (EtherEapol *) raw_pkt;

    if(len < sizeof(EtherEapol))
    {
        codec_events::decoder_event(p, DECODE_EAPOL_TRUNCATED);
        return false;
    }

    if (p->eplh->eaptype == EAPOL_TYPE_EAP) {
        DecodeEAP(raw_pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p);
    }
    else if(p->eplh->eaptype == EAPOL_TYPE_KEY) {
        DecodeEapolKey(raw_pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p);
    }

    return true;
}


void EapolCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_EAPOL);
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor()
{
    return new EapolCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const char* name = "eapol";
static const CodecApi eapol_api =
{
    {
        PT_CODEC,
        name,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr,
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &name_api.base,
    nullptr
};
#else
const BaseApi* cd_eapol = &eapol_api.base;
#endif

