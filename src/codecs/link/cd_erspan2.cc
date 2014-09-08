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
// cd_erspan2.cc author Josh Rosenbaum <jrosenba@cisco.com>


#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "protocols/protocol_ids.h"
#include "codecs/sf_protocols.h"
#include "protocols/packet.h"

#define CD_ERSPAN2_NAME "erspan2"
#define CD_ERSPAN2_HELP "support for encapsulated remote switched port analyzer - type 2"

namespace
{

static const RuleMap erspan2_rules[] =
{
    { DECODE_ERSPAN_HDR_VERSION_MISMATCH, "(codec_erspan) ERSpan Header version mismatch" },
    { DECODE_ERSPAN2_DGRAM_LT_HDR, "(" CD_ERSPAN2_NAME ") captured < ERSpan Type2 Header Length" },
    { 0, nullptr }
};

class Erspan2Module : public DecodeModule
{
public:
    Erspan2Module() : DecodeModule(CD_ERSPAN2_NAME, CD_ERSPAN2_HELP) {}

    const RuleMap* get_rules() const
    { return erspan2_rules; }
};


class Erspan2Codec : public Codec
{
public:
    Erspan2Codec() : Codec(CD_ERSPAN2_NAME){};
    ~Erspan2Codec(){};

    virtual PROTO_ID get_proto_id() { return PROTO_ERSPAN; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    
};


struct ERSpanType2Hdr
{
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t pad;
} ;

const uint16_t ETHERTYPE_ERSPAN_TYPE2 = 0x88be;
} // namespace


static inline uint16_t erspan_version(ERSpanType2Hdr *hdr)
{
    return (ntohs(hdr->ver_vlan) & 0xf000) >> 12;
}

void Erspan2Codec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_ERSPAN_TYPE2);
}


/*
 * Function: DecodeERSPANType2(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Encapsulated Remote Switch Packet Analysis Type 2
 *          This will decode ERSPAN Type 2 Headers
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 *
 */
bool Erspan2Codec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    lyr_len = sizeof(ERSpanType2Hdr);
    ERSpanType2Hdr *erSpan2Hdr = (ERSpanType2Hdr *)raw_pkt;

    if (raw_len < sizeof(ERSpanType2Hdr))
    {
        codec_events::decoder_event(p, DECODE_ERSPAN2_DGRAM_LT_HDR);
        return false;
    }

    p->encapsulations++;


    /* Check that this is in fact ERSpan Type 2.
     */
    if (erspan_version(erSpan2Hdr) != 0x01) /* Type 2 == version 0x01 */
    {
        codec_events::decoder_event(p, DECODE_ERSPAN_HDR_VERSION_MISMATCH);
        return false;
    }

    next_prot_id = ETHERTYPE_TRANS_ETHER_BRIDGING;
    return true;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Erspan2Module; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new Erspan2Codec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi erspan2_api =
{
    {
        PT_CODEC,
        CD_ERSPAN2_NAME,
        CD_ERSPAN2_HELP,
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
    &erspan2_api.base,
    nullptr
};
#else
const BaseApi* cd_erspan2 = &erspan2_api.base;
#endif
