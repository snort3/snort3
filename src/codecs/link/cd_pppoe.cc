//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// cd_pppoe.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"

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
    uint8_t ver_type;     /* pppoe version/type */
    uint8_t code;         /* pppoe code CODE_* */
    uint16_t session;     /* session id */
    uint16_t length;      /* payload length */
    /* payload follows */
};

//-------------------------------------------------------------------------
// General PPPoEpkt module.
//
//      ***** NOTE: THE CODEC HAS A DIFFERENT NAME!
//          * Additionally, this module is used for generating a rule stub ONLY!
//          * If you want to create a module for configuration, you must change the
//          * names of the correct PPPoEpkt codec
//-------------------------------------------------------------------------
#define CD_PPPOE_NAME "pppoe"
static const RuleMap pppoe_rules[] =
{
    { DECODE_BAD_PPPOE, "bad PPPOE frame detected" },
    { 0, nullptr }
};

#define pppoe_help \
    "support for point-to-point protocol over ethernet"

class PPPoEModule : public CodecModule
{
public:
    PPPoEModule() : CodecModule(CD_PPPOE_NAME, pppoe_help) { }

    const RuleMap* get_rules() const override
    { return pppoe_rules; }
};

class PPPoECodec : public Codec
{
public: ~PPPoECodec() { }

    bool decode(const RawData&, CodecData&, DecodeData&) override final;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override final;

protected:
    PPPoECodec(const char* s, PppoepktType type) :
        Codec(s),
        ppp_type(type)
    { }

private:
    PppoepktType ppp_type;
};
} // namespace

constexpr uint16_t PPPOE_HEADER_LEN = 6;

/* PPPoE types */
constexpr uint16_t PPPoE_CODE_SESS = 0x00; /* PPPoE session */
constexpr uint16_t PPPoE_CODE_PADI = 0x09; /* PPPoE Active Discovery Initiation */
constexpr uint16_t PPPoE_CODE_PADO = 0x07; /* PPPoE Active Discovery Offer */
constexpr uint16_t PPPoE_CODE_PADR = 0x19; /* PPPoE Active Discovery Request */
constexpr uint16_t PPPoE_CODE_PADS = 0x65; /* PPPoE Active Discovery Session-confirmation */
constexpr uint16_t PPPoE_CODE_PADT = 0xa7; /* PPPoE Active Discovery Terminate */

#if 0
/* PPPoE tag types  -  currently not used*/
constexpr uint16_t PPPoE_TAG_END_OF_LIST = 0x0000;
constexpr uint16_t PPPoE_TAG_SERVICE_NAME = 0x0101;
constexpr uint16_t PPPoE_TAG_AC_NAME = 0x0102;
constexpr uint16_t PPPoE_TAG_HOST_UNIQ = 0x0103;
constexpr uint16_t PPPoE_TAG_AC_COOKIE = 0x0104;
constexpr uint16_t PPPoE_TAG_VENDOR_SPECIFIC = 0x0105;
constexpr uint16_t PPPoE_TAG_RELAY_SESSION_ID = 0x0110;
constexpr uint16_t PPPoE_TAG_SERVICE_NAME_ERROR = 0x0201;
const uint16_t PPPoE_TAG_AC_SYSTEM_ERROR = 0x0202;
constexpr uint16_t PPPoE_TAG_GENERIC_ERROR = 0x0203;
#endif

bool PPPoECodec::decode(const RawData& raw,
    CodecData& codec,
    DecodeData&)
{
    if (raw.len < PPPOE_HEADER_LEN)
    {
        codec_event(codec, DECODE_BAD_PPPOE);
        return false;
    }

    /* lay the PPP over ethernet structure over the packet data */
    const PPPoEHdr* const pppoeh = reinterpret_cast<const PPPoEHdr*>(raw.data);

    /* grab out the network type */
    switch (ppp_type)
    {
    case PppoepktType::DISCOVERY:
        DebugMessage(DEBUG_DECODE, "(PPPOE Discovery) ");
        break;

    case PppoepktType::SESSION:
        DebugMessage(DEBUG_DECODE, "(PPPOE Session) ");
        break;
    }

#ifdef DEBUG_MSGS
    switch (pppoeh->code)
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

    if (ppp_type == PppoepktType::DISCOVERY)
    {
        DebugMessage(DEBUG_DECODE, "Returning early on PPPOE discovery packet\n");
        return true;
    }

    codec.lyr_len = PPPOE_HEADER_LEN;
    codec.next_prot_id = ProtocolId::ETHERTYPE_PPP;
    return true;
}

/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/

bool PPPoECodec::encode(const uint8_t* const raw_in, const uint16_t raw_len,
    EncState&, Buffer& buf, Flow*)
{
    if (!buf.allocate(raw_len))
        return false;

    memcpy(buf.data(), raw_in, raw_len);
    PPPoEHdr* const ppph = reinterpret_cast<PPPoEHdr*>(buf.data());
    ppph->length = htons((uint16_t)buf.size());

    return true;
}

/*******************************************************************
 *******************************************************************
 *************                  CODECS              ****************
 *******************************************************************
 *******************************************************************/

namespace
{
#define CD_PPPOEPKT_DISC_NAME "pppoe_disc"
#define CD_PPPOEPKT_DISC_HELP "support for point-to-point discovery"

#define CD_PPPOEPKT_SESS_NAME "pppoe_sess"
#define CD_PPPOEPKT_SESS_HELP "support for point-to-point session"

/*  'decode' and 'encode' functions are in the PPPoECodec */
class PPPoEDiscCodec : public PPPoECodec
{
public:
    PPPoEDiscCodec() : PPPoECodec(CD_PPPOEPKT_DISC_NAME, PppoepktType::DISCOVERY) { }
    ~PPPoEDiscCodec() { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override
    { v.push_back(ProtocolId::ETHERTYPE_PPPOE_DISC); }
};

class PPPoESessCodec : public PPPoECodec
{
public:
    PPPoESessCodec() : PPPoECodec(CD_PPPOEPKT_SESS_NAME, PppoepktType::SESSION) { }
    ~PPPoESessCodec() { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override
    { v.push_back(ProtocolId::ETHERTYPE_PPPOE_SESS); }
};
} // namespace

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

// ***  NOTE: THE CODEC AND MODULE HAVE A DIFFERENT NAME!
// since the module is only creating a rule stub and is NOT
// used for configuration, it doesn't matter. However, if you want to use the module
// for configuration, ensure the names are identical before continuing!
static Module* mod_ctor()
{ return new PPPoEModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* disc_ctor(Module*)
{ return new PPPoEDiscCodec(); }

static Codec* sess_ctor(Module*)
{ return new PPPoESessCodec(); }

static void pppoe_dtor(Codec* cd)
{ delete cd; }

static const CodecApi pppoepkt_disc_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_PPPOEPKT_DISC_NAME,
        CD_PPPOEPKT_DISC_HELP,
        mod_ctor,
        mod_dtor,
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    disc_ctor,
    pppoe_dtor,
};

static const CodecApi pppoepkt_sess_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_PPPOEPKT_SESS_NAME,
        CD_PPPOEPKT_SESS_HELP,
        nullptr,
        nullptr,
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    sess_ctor,
    pppoe_dtor,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* cd_pppoepkt[] =
#endif
{
    &pppoepkt_disc_api.base,
    &pppoepkt_sess_api.base,
    nullptr
};

