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
// cd_eapol.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "protocols/protocol_ids.h"
#include "protocols/eapol.h"


namespace
{

#define CD_EAPOL_NAME "eapol"
static const RuleMap eapol_rules[] =
{
    { DECODE_EAPOL_TRUNCATED, "(" CD_EAPOL_NAME ") Truncated EAP Header" },
    { DECODE_EAPKEY_TRUNCATED, "(" CD_EAPOL_NAME ") EAP Key Truncated" },
    { DECODE_EAP_TRUNCATED, "(" CD_EAPOL_NAME ") EAP Header Truncated" },
    { 0, nullptr }
};

static const char* eapol_help =
    "support for extensible authentication protocol over LAN";

class EapolModule : public DecodeModule
{
public:
    EapolModule() : DecodeModule(CD_EAPOL_NAME, eapol_help) {}

    const RuleMap* get_rules() const
    { return eapol_rules; }
};

class EapolCodec : public Codec
{
public:
    EapolCodec() : Codec(CD_EAPOL_NAME){};
    ~EapolCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    
};

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
    const eapol::EAPHdr *eaph = reinterpret_cast<const eapol::EAPHdr*>(pkt);

    if(len < sizeof(eapol::EAPHdr))
    {
        codec_events::decoder_event(p, DECODE_EAP_TRUNCATED);
        return;
    }
    if (eaph->code == EAP_CODE_REQUEST ||
            eaph->code == EAP_CODE_RESPONSE) {
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
void DecodeEapolKey(const uint8_t* /*pkt*/, uint32_t len, Packet * p)
{
    if(len < sizeof(eapol::EapolKey))
    {
        codec_events::decoder_event(p, DECODE_EAPKEY_TRUNCATED);
    }

    return;
}


/*************************************************
 ************** main codec functions  ************
 *************************************************/

bool EapolCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t & /*lyr_len*/, uint16_t &/*next_prot_id */)
{
    const eapol::EtherEapol* eplh = reinterpret_cast<const eapol::EtherEapol*>(raw_pkt);

    if(raw_len < sizeof(eapol::EtherEapol))
    {
        codec_events::decoder_event(p, DECODE_EAPOL_TRUNCATED);
        return false;
    }

    if (eplh->eaptype == EAPOL_TYPE_EAP) {
        DecodeEAP(raw_pkt + sizeof(eapol::EtherEapol), raw_len - sizeof(eapol::EtherEapol), p);
    }
    else if(eplh->eaptype == EAPOL_TYPE_KEY) {
        DecodeEapolKey(raw_pkt + sizeof(eapol::EtherEapol), raw_len - sizeof(eapol::EtherEapol), p);
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

static Module* mod_ctor()
{
    return new EapolModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Codec* ctor(Module*)
{
    return new EapolCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi eapol_api =
{
    {
        PT_CODEC,
        CD_EAPOL_NAME,
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


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &eapol_api.base,
    nullptr
};
#else
const BaseApi* cd_eapol = &eapol_api.base;
#endif
