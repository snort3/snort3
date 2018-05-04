//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

using namespace snort;

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
public:
    bool decode(const RawData&, CodecData&, DecodeData&) final;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) final;

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

bool PPPoECodec::decode(const RawData& raw,
    CodecData& codec,
    DecodeData&)
{
    if (raw.len < PPPOE_HEADER_LEN)
    {
        codec_event(codec, DECODE_BAD_PPPOE);
        return false;
    }

    if (ppp_type == PppoepktType::DISCOVERY)
    {
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

    void get_protocol_ids(std::vector<ProtocolId>& v) override
    { v.push_back(ProtocolId::ETHERTYPE_PPPOE_DISC); }
};

class PPPoESessCodec : public PPPoECodec
{
public:
    PPPoESessCodec() : PPPoECodec(CD_PPPOEPKT_SESS_NAME, PppoepktType::SESSION) { }

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

