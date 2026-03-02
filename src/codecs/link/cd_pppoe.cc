//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

/* PPPoEHdr Header; eth::EtherHdr plus the PPPoE Header */
struct PPPoEHdr
{
    // cppcheck-suppress unusedStructMember
    uint8_t ver_type;     /* pppoe version/type */
    // cppcheck-suppress unusedStructMember
    uint8_t code;         /* pppoe code CODE_* */
    // cppcheck-suppress unusedStructMember
    uint16_t session;     /* session id */
    uint16_t length;      /* payload length */
    /* payload follows */
};

//-------------------------------------------------------------------------
// General PPPoEpkt module.
//-------------------------------------------------------------------------

static const RuleMap pppoe_disc_rules[] =
{
    { DECODE_BAD_PPPOE_DISC, "bad PPPOE discovery frame detected" },
    { 0, nullptr }
};

static const RuleMap pppoe_sess_rules[] =
{
    { DECODE_BAD_PPPOE_SESS, "bad PPPOE session frame detected" },
    { 0, nullptr }
};

class PPPoEModule : public BaseCodecModule
{
public:
    PPPoEModule(const char* name, const char* help, const RuleMap* rm) : BaseCodecModule(name, help)
    { rules = rm; }

    const RuleMap* get_rules() const override
    { return rules; }

private:
    const RuleMap* rules;
};

class PPPoECodec : public Codec
{
public:
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) final;

protected:
    PPPoECodec(const char* s) : Codec(s) { }
};
} // namespace

constexpr uint16_t PPPOE_HEADER_LEN = 6;

/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/

bool PPPoECodec::encode(const uint8_t* const raw_in, const uint16_t raw_len,
    EncState& enc, Buffer& buf, Flow*)
{
    if (!buf.allocate(raw_len))
        return false;

    memcpy(buf.data(), raw_in, raw_len);
    PPPoEHdr* const ppph = reinterpret_cast<PPPoEHdr*>(buf.data());
    ppph->length = htons((uint16_t)buf.size() - raw_len);

    enc.next_ethertype = ProtocolId::ETHERTYPE_NOT_SET;
    enc.next_proto = IpProtocol::PROTO_NOT_SET;
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

class PPPoEDiscCodec : public PPPoECodec
{
public:
    PPPoEDiscCodec() : PPPoECodec(CD_PPPOEPKT_DISC_NAME) { }
    bool decode(const RawData&, CodecData&, DecodeData&) final;

    void get_protocol_ids(std::vector<ProtocolId>& v) override
    { v.emplace_back(ProtocolId::ETHERTYPE_PPPOE_DISC); }
};

bool PPPoEDiscCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < PPPOE_HEADER_LEN)
    {
        codec_event(codec, DECODE_BAD_PPPOE_DISC);
        return false;
    }

    return true;
}

#define CD_PPPOEPKT_SESS_NAME "pppoe_sess"
#define CD_PPPOEPKT_SESS_HELP "support for point-to-point session"

class PPPoESessCodec : public PPPoECodec
{
public:
    PPPoESessCodec() : PPPoECodec(CD_PPPOEPKT_SESS_NAME) { }
    bool decode(const RawData&, CodecData&, DecodeData&) final;

    void get_protocol_ids(std::vector<ProtocolId>& v) override
    { v.emplace_back(ProtocolId::ETHERTYPE_PPPOE_SESS); }
};

bool PPPoESessCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < PPPOE_HEADER_LEN)
    {
        codec_event(codec, DECODE_BAD_PPPOE_SESS);
        return false;
    }

    codec.lyr_len = PPPOE_HEADER_LEN;
    codec.next_prot_id = ProtocolId::ETHERTYPE_PPP;
    return true;
}

} // namespace

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* disc_mod_ctor()
{ return new PPPoEModule(CD_PPPOEPKT_DISC_NAME, CD_PPPOEPKT_DISC_HELP, pppoe_disc_rules); }

static Module* sess_mod_ctor()
{ return new PPPoEModule(CD_PPPOEPKT_SESS_NAME, CD_PPPOEPKT_SESS_HELP, pppoe_sess_rules); }

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
        PLUGIN_SO_RELOAD,
        API_OPTIONS,
        CD_PPPOEPKT_DISC_NAME,
        CD_PPPOEPKT_DISC_HELP,
        disc_mod_ctor,
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
        PLUGIN_SO_RELOAD,
        API_OPTIONS,
        CD_PPPOEPKT_SESS_NAME,
        CD_PPPOEPKT_SESS_HELP,
        sess_mod_ctor,
        mod_dtor,
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

