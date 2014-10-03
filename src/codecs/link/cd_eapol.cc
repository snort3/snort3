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

#define CD_EAPOL_NAME "eapol"
#define CD_EAPOL_HELP "support for extensible authentication protocol over LAN"

namespace
{

static const RuleMap eapol_rules[] =
{
    { DECODE_EAPOL_TRUNCATED, "(" CD_EAPOL_NAME ") Truncated EAP Header" },
    { DECODE_EAPKEY_TRUNCATED, "(" CD_EAPOL_NAME ") EAP Key Truncated" },
    { DECODE_EAP_TRUNCATED, "(" CD_EAPOL_NAME ") EAP Header Truncated" },
    { 0, nullptr }
};

class EapolModule : public DecodeModule
{
public:
    EapolModule() : DecodeModule(CD_EAPOL_NAME, CD_EAPOL_HELP) {}

    const RuleMap* get_rules() const
    { return eapol_rules; }
};

class EapolCodec : public Codec
{
public:
    EapolCodec() : Codec(CD_EAPOL_NAME){};
    ~EapolCodec() {};


    virtual bool decode(const RawData&, CodecData&, DecodeData&);
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
void DecodeEAP(const RawData& raw, const CodecData& codec)
{
    if(raw.len < sizeof(eapol::EAPHdr))
        codec_events::decoder_event(codec, DECODE_EAP_TRUNCATED);
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
void DecodeEapolKey(const RawData& raw, const CodecData& codec)
{
    if(raw.len < sizeof(eapol::EapolKey))
        codec_events::decoder_event(codec, DECODE_EAPKEY_TRUNCATED);
}


/*************************************************
 ************** main codec functions  ************
 *************************************************/

bool EapolCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const eapol::EtherEapol* const eplh =
        reinterpret_cast<const eapol::EtherEapol*>(raw.data);

    if(raw.len < sizeof(eapol::EtherEapol))
    {
        codec_events::decoder_event(codec, DECODE_EAPOL_TRUNCATED);
        return false;
    }

    if (eplh->eaptype == EAPOL_TYPE_EAP)
        DecodeEAP(raw, codec);

    else if(eplh->eaptype == EAPOL_TYPE_KEY)
        DecodeEapolKey(raw, codec);

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
{ return new EapolModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new EapolCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi eapol_api =
{
    {
        PT_CODEC,
        CD_EAPOL_NAME,
        CD_EAPOL_HELP,
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
