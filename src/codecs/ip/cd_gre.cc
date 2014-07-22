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
// cd_gre.cc author Josh Rosenbaum <jrosenba@cisco.com>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/ip/cd_gre_module.h"
#include "codecs/codec_events.h"
#include "protocols/packet.h"
#include "protocols/protocol_ids.h"
#include "codecs/sf_protocols.h"
#include "protocols/gre.h"

namespace
{

class GreCodec : public Codec
{
public:
    GreCodec() : Codec(CD_GRE_NAME){};
    ~GreCodec(){};

    virtual PROTO_ID get_proto_id() { return PROTO_GRE; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);


};

static const uint32_t GRE_HEADER_LEN = 4;
static const uint32_t GRE_CHKSUM_LEN = 2;
static const uint32_t GRE_OFFSET_LEN = 2;
static const uint32_t GRE_KEY_LEN = 4;
static const uint32_t GRE_SEQ_LEN = 4;
static const uint32_t GRE_SRE_HEADER_LEN = 4;

/* GRE version 1 used with PPTP */
/* static const uint32_t GRE_V1_HEADER_LEN == GRE_HEADER_LEN + GRE_KEY_LEN; */
static const uint32_t GRE_V1_ACK_LEN = 4;

#define GRE_V1_FLAGS(x)   (x->version & 0x78)
#define GRE_V1_ACK(x)     (x->version & 0x80)
#define GRE_CHKSUM(x)  (x->flags & 0x80)
#define GRE_ROUTE(x)   (x->flags & 0x40)
#define GRE_KEY(x)     (x->flags & 0x20)
#define GRE_SEQ(x)     (x->flags & 0x10)
#define GRE_SSR(x)     (x->flags & 0x08)
#define GRE_RECUR(x)   (x->flags & 0x07)
#define GRE_FLAGS(x)   (x->version & 0xF8)

} // anonymous namespace


void GreCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_GRE);
}


/*
 * Function: DecodeGRE(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Generic Routing Encapsulation Protocol
 *          This will decode normal GRE and PPTP GRE.
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 *
 * Notes: see RFCs 1701, 2784 and 2637
 */
bool GreCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    if (len < GRE_HEADER_LEN)
    {
        codec_events::decoder_alert_encapsulated(p, DECODE_GRE_DGRAM_LT_GREHDR,
                        raw_pkt, len);
        return false;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple GRE encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        codec_events::decoder_alert_encapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION,
                        raw_pkt, len);
        return false;
    }

    /* Note: Since GRE doesn't have a field to indicate header length and
     * can contain a few options, we need to walk through the header to
     * figure out the length
     */

    const gre::GREHdr *greh = reinterpret_cast<const gre::GREHdr *>(raw_pkt);
    lyr_len = GRE_HEADER_LEN;

    switch (GRE_VERSION(greh))
    {
        case 0x00:
            /* these must not be set */
            if (GRE_RECUR(greh) || GRE_FLAGS(greh))
            {
                codec_events::decoder_alert_encapsulated(p, DECODE_GRE_INVALID_HEADER,
                                raw_pkt, len);
                return false;
            }

            if (GRE_CHKSUM(greh) || GRE_ROUTE(greh))
                lyr_len += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;

            if (GRE_KEY(greh))
                lyr_len += GRE_KEY_LEN;

            if (GRE_SEQ(greh))
                lyr_len += GRE_SEQ_LEN;

            /* if this flag is set, we need to walk through all of the
             * Source Route Entries */
            if (GRE_ROUTE(greh))
            {
                uint16_t sre_addrfamily;
                uint8_t sre_offset;
                uint8_t sre_length;
                const uint8_t *sre_ptr;

                sre_ptr = raw_pkt + lyr_len;

                while (1)
                {
                    lyr_len += GRE_SRE_HEADER_LEN;
                    if (lyr_len > len)
                        break;

                    sre_addrfamily = ntohs(*((uint16_t *)sre_ptr));
                    sre_ptr += sizeof(sre_addrfamily);

                    sre_ptr += sizeof(sre_offset);

                    sre_length = *((uint8_t *)sre_ptr);
                    sre_ptr += sizeof(sre_length);

                    if ((sre_addrfamily == 0) && (sre_length == 0))
                        break;

                    lyr_len += sre_length;
                    sre_ptr += sre_length;
                }
            }

            break;

        /* PPTP */
        case 0x01:
            /* these flags should never be present */
            if (GRE_CHKSUM(greh) || GRE_ROUTE(greh) || GRE_SSR(greh) ||
                GRE_RECUR(greh) || GRE_V1_FLAGS(greh))
            {
                codec_events::decoder_alert_encapsulated(p, DECODE_GRE_V1_INVALID_HEADER,
                                raw_pkt, len);
                return false;
            }

            /* protocol must be 0x880B - PPP */
            if (GRE_PROTO(greh) != ETHERTYPE_PPP)
            {
                codec_events::decoder_alert_encapsulated(p, DECODE_GRE_V1_INVALID_HEADER,
                                raw_pkt, len);
                return false;
            }

            /* this flag should always be present */
            if (!(GRE_KEY(greh)))
            {
                codec_events::decoder_alert_encapsulated(p, DECODE_GRE_V1_INVALID_HEADER,
                                raw_pkt, len);
                return false;
            }

            lyr_len += GRE_KEY_LEN;

            if (GRE_SEQ(greh))
                lyr_len += GRE_SEQ_LEN;

            if (GRE_V1_ACK(greh))
                lyr_len += GRE_V1_ACK_LEN;

            break;

        default:
            codec_events::decoder_alert_encapsulated(p, DECODE_GRE_INVALID_VERSION,
                            raw_pkt, len);
            return false;
    }

    if (lyr_len > len)
    {
        codec_events::decoder_alert_encapsulated(p, DECODE_GRE_DGRAM_LT_GREHDR,
                        raw_pkt, len);
        return false;
    }

    next_prot_id = GRE_PROTO(greh);
    return true;
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new GreModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Codec* ctor(Module*)
{
    return new GreCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi gre_api =
{
    {
        PT_CODEC,
        CD_GRE_NAME,
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
    &gre_api.base,
    nullptr
};
#else
const BaseApi* cd_gre = &gre_api.base;
#endif


