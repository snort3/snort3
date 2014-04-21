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



#include "framework/codec.h"
#include "codecs/codec_events.h"
#include "codecs/decode_module.h"


namespace
{

class PPPoEPkt : public Codec
{
public:
    PPPoEPkt() : Codec("PPP_over_Eth"){};
    ~PPPoEPkt(){};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &p_hdr_len, int &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    
};


const uint16_t PPPOE_HEADER_LEN = 6;

const uint16_t ETHERNET_TYPE_PPPoE_DISC =  0x8863; /* discovery stage */
const uint16_t ETHERNET_TYPE_PPPoE_SESS =  0x8864; /* session stage */

/* PPPoE types */
const uint16_t PPPoE_CODE_SESS = 0x00; /* PPPoE session */
const uint16_t PPPoE_CODE_PADI = 0x09; /* PPPoE Active Discovery Initiation */
const uint16_t PPPoE_CODE_PADO = 0x07; /* PPPoE Active Discovery Offer */
const uint16_t PPPoE_CODE_PADR = 0x19; /* PPPoE Active Discovery Request */
const uint16_t PPPoE_CODE_PADS = 0x65; /* PPPoE Active Discovery Session-confirmation */
const uint16_t PPPoE_CODE_PADT = 0xa7; /* PPPoE Active Discovery Terminate */

/* PPPoE tag types */
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


} // anonymous namespace


//--------------------------------------------------------------------
// decode.c::PPP related
//--------------------------------------------------------------------

/*
 * Function: DecodePPPoEPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 * see http://www.faqs.org/rfcs/rfc2516.html
 *
 */
bool PPPoEPkt::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, int &next_prot_id)
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

        DecoderEvent(p, DECODE_BAD_PPPOE);

        return false;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%X   %X\n",
                *p->eh->ether_src, *p->eh->ether_dst););

    /* lay the PPP over ethernet structure over the packet data */
    p->pppoeh = (PPPoEHdr *)raw_pkt;

    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_PPPoE_DISC:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Discovery) "););
            break;

        case ETHERNET_TYPE_PPPoE_SESS:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Session) "););
            break;

        default:
            return false;
    }

#ifdef DEBUG_MSGS
    switch(p->pppoeh->code)
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
#endif

    if (ntohs(p->eh->ether_type) != ETHERNET_TYPE_PPPoE_DISC)
    {
//        PushLayer(PROTO_PPPOE, p, pkt, PPPOE_HEADER_LEN);
//        DecodePppPktEncapsulated(pkt + PPPOE_HEADER_LEN, len - PPPOE_HEADER_LEN, p);

        // TODO:  Why is this specifically PppPktEncapsulated?
        p_hdr_len = PPPOE_HEADER_LEN;
        next_prot_id = ntohs(p->eh->ether_type);
        return true;
    }


    return false;
}

#if 0

EncStatus PPPoE_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int n = enc->p->layers[enc->layer-1].length;
    int len;

    PPPoEHdr* hi = (PPPoEHdr*)(enc->p->layers[enc->layer-1].start);
    PPPoEHdr* ho = (PPPoEHdr*)(out->base + out->end);

    uint32_t start;
    PROTO_ID next = NextEncoder(enc);

    UPDATE_BOUND(out, n);
    memcpy(ho, hi, n);

    start = out->end;

    if ( next < PROTO_MAX )
    {
        EncStatus err = encoders[next].fencode(enc, in, out);
        if (EncStatus::ENC_OK != err ) return err;
    }
    len = out->end - start;
    ho->length = htons((uint16_t)len);

    return EncStatus::ENC_OK;
}
#endif

void PPPoEPkt::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERNET_TYPE_PPPoE_DISC);
    v.push_back(ETHERNET_TYPE_PPPoE_SESS);
}

static Codec* ctor()
{
    return new PPPoEPkt();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static void sum()
{
//    sum_stats((PegCount*)&gdc, (PegCount*)&dc, array_size(dc_pegs));
//    memset(&dc, 0, sizeof(dc));
}

static void stats()
{
//    show_percent_stats((PegCount*)&gdc, dc_pegs, array_size(dc_pegs),
//        "decoder");
}



static const char* name = "pppoe_codec";

static const CodecApi pppoe_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    sum, // sum
    stats  // stats
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pppoe_api.base,
    nullptr
};
#else
const BaseApi* cd_pppoe = &pppoe_api.base;
#endif



