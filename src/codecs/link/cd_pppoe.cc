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
// cd_pppoepkt.cc author Josh Rosenbaum <jrosenba@cisco.com>



#include "framework/codec.h"
#include "codecs/link/cd_pppoe_module.h"
#include "codecs/codec_events.h"
#include "protocols/packet.h"
#include "codecs/sf_protocols.h"
#include "protocols/layer.h"

namespace
{

enum class PppoepktType
{
    DISCOVERY,
    SESSION,
};

/* PPPoEHdr Header; eth::EtherHdr plus the PPPoE Header */
struct PPPoEHdr
{
    unsigned char ver_type;     /* pppoe version/type */
    unsigned char code;         /* pppoe code CODE_* */
    unsigned short session;     /* session id */
    unsigned short length;      /* payload length */
                                /* payload follows */
};

} // namespace


const uint16_t PPPOE_HEADER_LEN = 6;

/* PPPoE types */
const uint16_t PPPoE_CODE_SESS = 0x00; /* PPPoE session */
const uint16_t PPPoE_CODE_PADI = 0x09; /* PPPoE Active Discovery Initiation */
const uint16_t PPPoE_CODE_PADO = 0x07; /* PPPoE Active Discovery Offer */
const uint16_t PPPoE_CODE_PADR = 0x19; /* PPPoE Active Discovery Request */
const uint16_t PPPoE_CODE_PADS = 0x65; /* PPPoE Active Discovery Session-confirmation */
const uint16_t PPPoE_CODE_PADT = 0xa7; /* PPPoE Active Discovery Terminate */

#if 0
/* PPPoE tag types  -  currently not used*/
const uint16_t PPPoE_TAG_END_OF_LIST = 0x0000;
const uint16_t PPPoE_TAG_SERVICE_NAME = 0x0101;
const uint16_t PPPoE_TAG_AC_NAME = 0x0102;
const uint16_t PPPoE_TAG_HOST_UNIQ = 0x0103;
const uint16_t PPPoE_TAG_AC_COOKIE = 0x0104;
const uint16_t PPPoE_TAG_VENDOR_SPECIFIC = 0x0105;
const uint16_t PPPoE_TAG_RELAY_SESSION_ID = 0x0110;
const uint16_t PPPoE_TAG_SERVICE_NAME_ERROR = 0x0201;
const uint16_t PPPoE_TAG_AC_SYSTEM_ERROR = 0x0202;
const uint16_t PPPoE_TAG_GENERIC_ERROR = 0x0203;
#endif


static inline bool pppoepkt_decode(const uint8_t *raw_pkt,
                                    const uint32_t len,
                                    Packet *p,
                                    PppoepktType ppp_type,
                                    uint16_t &lyr_len,
                                    uint16_t &next_prot_id)
{
    //PPPoE_Tag *ppppoe_tag=0;
    //PPPoE_Tag tag;  /* needed to avoid alignment problems */

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "PPPoE with len: %lu\n",
        (unsigned long)len););

    /* do a little validation */
    if(len < PPPOE_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Captured data length < PPPoE header length! "
            "(%d bytes)\n", len););

        codec_events::decoder_event(p, DECODE_BAD_PPPOE);

        return false;
    }


    /* lay the PPP over ethernet structure over the packet data */
    const PPPoEHdr *pppoeh = reinterpret_cast<const PPPoEHdr*>(raw_pkt);

    /* grab out the network type */
    switch(ppp_type)
    {
        case PppoepktType::DISCOVERY:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Discovery) "););
            break;

        case PppoepktType::SESSION:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Session) "););
            break;
    }

#ifdef DEBUG_MSGS
    switch(pppoeh->code)
    {
        case PPPoE_CODE_PADI:
            /* The Host sends the PADI packet with the DESTINATION_ADDR set
             * to the broadcast address.  The CODE field is set to 0x09 and
             * the SESSION_ID MUST be set to 0x0000.
             *
             * The PADI packet MUST contain exactly one TAG of TAG_TYPE
             * Service-Name, indicating the service the Host is requesting,
             * and any number of other TAG types.  An entire PADI packet
             * (including the PPPoE header) MUST NOT exceed 1484 octets so
             * as to leave sufficient room for a relay agent to add a
             * Relay-Session-Id TAG.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery Initiation (PADI)\n");
            break;

        case PPPoE_CODE_PADO:
            /* When the Access Concentrator receives a PADI that it can
             * serve, it replies by sending a PADO packet.  The
             * DESTINATION_ADDR is the unicast address of the Host that
             * sent the PADI.  The CODE field is set to 0x07 and the
             * SESSION_ID MUST be set to 0x0000.
             *
             * The PADO packet MUST contain one AC-Name TAG containing the
             * Access Concentrator's name, a Service-Name TAG identical to
             * the one in the PADI, and any number of other Service-Name
             * TAGs indicating other services that the Access Concentrator
             * offers.  If the Access Concentrator can not serve the PADI
             * it MUST NOT respond with a PADO.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery Offer (PADO)\n");
            break;

        case PPPoE_CODE_PADR:
            /* Since the PADI was broadcast, the Host may receive more than
             * one PADO.  The Host looks through the PADO packets it receives
             * and chooses one.  The choice can be based on the AC-Name or
             * the Services offered.  The Host then sends one PADR packet
             * to the Access Concentrator that it has chosen.  The
             * DESTINATION_ADDR field is set to the unicast Ethernet address
             * of the Access Concentrator that sent the PADO.  The CODE
             * field is set to 0x19 and the SESSION_ID MUST be set to 0x0000.
             *
             * The PADR packet MUST contain exactly one TAG of TAG_TYPE
             * Service-Name, indicating the service the Host is requesting,
             * and any number of other TAG types.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery Request (PADR)\n");
            break;

        case PPPoE_CODE_PADS:
            /* When the Access Concentrator receives a PADR packet, it
             * prepares to begin a PPP session.  It generates a unique
             * SESSION_ID for the PPPoE session and replies to the Host with
             * a PADS packet.  The DESTINATION_ADDR field is the unicast
             * Ethernet address of the Host that sent the PADR.  The CODE
             * field is set to 0x65 and the SESSION_ID MUST be set to the
             * unique value generated for this PPPoE session.
             *
             * The PADS packet contains exactly one TAG of TAG_TYPE
             * Service-Name, indicating the service under which Access
             * Concentrator has accepted the PPPoE session, and any number
             * of other TAG types.
             *
             * If the Access Concentrator does not like the Service-Name in
             * the PADR, then it MUST reply with a PADS containing a TAG of
             * TAG_TYPE Service-Name-Error (and any number of other TAG
             * types).  In this case the SESSION_ID MUST be set to 0x0000.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery "
                         "Session-confirmation (PADS)\n");
            break;

        case PPPoE_CODE_PADT:
            /* This packet may be sent anytime after a session is established
             * to indicate that a PPPoE session has been terminated.  It may
             * be sent by either the Host or the Access Concentrator.  The
             * DESTINATION_ADDR field is a unicast Ethernet address, the
             * CODE field is set to 0xa7 and the SESSION_ID MUST be set to
             * indicate which session is to be terminated.  No TAGs are
             * required.
             *
             * When a PADT is received, no further PPP traffic is allowed to
             * be sent using that session.  Even normal PPP termination
             * packets MUST NOT be sent after sending or receiving a PADT.
             * A PPP peer SHOULD use the PPP protocol itself to bring down a
             * PPPoE session, but the PADT MAY be used when PPP can not be
             * used.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery Terminate (PADT)\n");
            break;

        case PPPoE_CODE_SESS:
            DebugMessage(DEBUG_DECODE, "Session Packet (SESS)\n");
            break;

        default:
            DebugMessage(DEBUG_DECODE, "(Unknown)\n");
            break;
    }
#else
    UNUSED(pppoeh);
    UNUSED(PPPoE_CODE_SESS);
    UNUSED(PPPoE_CODE_PADI);
    UNUSED(PPPoE_CODE_PADO);
    UNUSED(PPPoE_CODE_PADR);
    UNUSED(PPPoE_CODE_PADS);
    UNUSED(PPPoE_CODE_PADT);
#endif

    if (ppp_type != PppoepktType::DISCOVERY)
    {
        lyr_len = PPPOE_HEADER_LEN;
        next_prot_id = ETHERTYPE_PPP;
        return true;
    }


    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Returning early on PPPOE discovery packet\n"););
    return true;
}


/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/

static inline bool pppoepkt_encode(EncState* enc, Buffer* out, const uint8_t* raw_in)
{
    int lyr_len = enc->p->layers[enc->layer-1].length;

    if (!update_buffer(out, lyr_len))
        return false;

    const PPPoEHdr* hi = reinterpret_cast<const PPPoEHdr*>(raw_in);
    PPPoEHdr* ho = reinterpret_cast<PPPoEHdr*>(out->base);

    memcpy(ho, hi, lyr_len);
    ho->length = htons((uint16_t)out->end);

    return true;
}


/*******************************************************************
 *******************************************************************
 *************                  CODECS              ****************
 *******************************************************************
 *******************************************************************/


namespace
{

const uint16_t ETHERNET_TYPE_PPPoE_DISC =  0x8863; /* discovery stage */
#define CD_PPPOEPKT_DISC_NAME "pppoe_disc"

class PPPoEDiscCodec : public Codec
{
public:
    PPPoEDiscCodec() : Codec(CD_PPPOEPKT_DISC_NAME){};
    ~PPPoEDiscCodec() {};


    virtual PROTO_ID get_proto_id() { return PROTO_PPPOE; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual bool encode(EncState*, Buffer* out, const uint8_t* raw_in);
};


} // namespace

void PPPoEDiscCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERNET_TYPE_PPPoE_DISC);
}


bool PPPoEDiscCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    return pppoepkt_decode(raw_pkt, raw_len, p, PppoepktType::DISCOVERY,
        lyr_len, next_prot_id);
}

bool PPPoEDiscCodec::encode(EncState *enc, Buffer* out, const uint8_t* raw_in)
{
    return pppoepkt_encode(enc, out, raw_in);
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


// ***  NOTE: THE CODEC HAS A DIFFERENT NAME!
// However, since the module is creating a rule stub and is NOT
// used for configurtion, it doesn't matter.  If you want to use the module
// for configuration, ensure the names are identical before continuing!
static Module* mod_ctor()
{
    return new PPPoEModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Codec* disc_ctor(Module*)
{
    return new PPPoEDiscCodec();
}

static void disc_dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi pppoepkt_disc_api =
{
    {
        PT_CODEC,
        CD_PPPOEPKT_DISC_NAME,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor,
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    disc_ctor,
    disc_dtor,
};




/*******************************************************************
 *******************************************************************
 *******************************************************************
 *******************************************************************/




namespace
{


#define CD_PPPOEPKT_SESS_NAME "pppoe_sess"

const uint16_t ETHERNET_TYPE_PPPoE_SESS =  0x8864; /* session stage */

class PPPoESessCodec : public Codec
{
public:
    PPPoESessCodec() : Codec(CD_PPPOEPKT_SESS_NAME){};
    ~PPPoESessCodec() {};


    virtual PROTO_ID get_proto_id() { return PROTO_PPPOE; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual bool encode(EncState*, Buffer* out, const uint8_t* raw_in);
};


} // namespace

void PPPoESessCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERNET_TYPE_PPPoE_SESS);
}


bool PPPoESessCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    return pppoepkt_decode(raw_pkt, raw_len, p, PppoepktType::SESSION,
        lyr_len, next_prot_id);
}



bool PPPoESessCodec::encode(EncState *enc, Buffer* out, const uint8_t* raw_in)
{
    return pppoepkt_encode(enc, out, raw_in);
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* sess_ctor(Module*)
{
    return new PPPoESessCodec();
}

static void sess_dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi pppoepkt_sess_api =
{
    {
        PT_CODEC,
        CD_PPPOEPKT_SESS_NAME,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr,
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    sess_ctor,
    sess_dtor,
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pppoepkt_disc_api.base,
    &pppoepkt_sess_api.base,
    nullptr
};
#else
const BaseApi* cd_pppoepkt_disc = &pppoepkt_disc_api.base;
const BaseApi* cd_pppoepkt_sess = &pppoepkt_sess_api.base;
#endif
