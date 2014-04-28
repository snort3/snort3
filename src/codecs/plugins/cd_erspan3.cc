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
// cd_erspan3.cc author Josh Rosenbaum <jorosenba@cisco.com>



#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "events/codec_events.h"
#include "protocols/ethertypes.h"


namespace
{

class Erspan3Codec : public Codec
{
public:
    Erspan3Codec() : Codec("ERSPAN_3"){};
    ~Erspan3Codec(){};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, int &next_prot_id);
    
    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_ERSPAN; };
};


struct ERSpanType3Hdr
{
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t timestamp;
    uint16_t pad0;
    uint16_t pad1;
    uint32_t pad2;
    uint32_t pad3;
};

const uint16_t ETHERTYPE_ERSPAN_TYPE3 = 0x22eb;
} // anonymous namespace

/*
 * Function: DecodeERSPANType3(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Encapsulated Remote Switch Packet Analysis Type 3
 *          This will decode ERSPAN Type 3 Headers
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 *
 */
bool Erspan3Codec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, int &next_prot_id)
{
    lyr_len= sizeof(ERSpanType3Hdr);
    uint32_t payload_len;
    ERSpanType3Hdr *erSpan3Hdr = (ERSpanType3Hdr *)raw_pkt;

    if (len < sizeof(ERSpanType3Hdr))
    {
        codec_events::decoder_alert_encapsulated(p, DECODE_ERSPAN3_DGRAM_LT_HDR,
                        raw_pkt, len);
        return false;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        codec_events::decoder_alert_encapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION,
                        raw_pkt, len);
        return false;
    }

    /* Check that this is in fact ERSpan Type 3.
     */
    if (ERSPAN_VERSION(erSpan3Hdr) != 0x02) /* Type 3 == version 0x02 */
    {
        codec_events::decoder_alert_encapsulated(p, DECODE_ERSPAN_HDR_VERSION_MISMATCH,
                        raw_pkt, len);
        return false;
    }


    next_prot_id = ETHERTYPE_TRANS_ETHER_BRIDGING;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static void get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_ERSPAN_TYPE3);
}

static Codec* ctor()
{
    return new Erspan3Codec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const char* name = "erspan3_codec";
static const CodecApi erspan3_api =
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
    &erspan3_api.base,
    nullptr
};
#else
const BaseApi* cd_erspan3 = &erspan3_api.base;
#endif
