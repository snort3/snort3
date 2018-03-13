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
// cd_esp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"

using namespace snort;

#define CD_ESP_NAME "esp"
#define CD_ESP_HELP "support for encapsulating security payload"

namespace
{
static const RuleMap esp_rules[] =
{
    { DECODE_ESP_HEADER_TRUNC, "truncated encapsulated security payload header" },
    { 0, nullptr }
};

static const Parameter esp_params[] =
{
    { "decode_esp", Parameter::PT_BOOL, nullptr, "false",
      "enable for inspection of esp traffic that has authentication but not encryption" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class EspModule : public CodecModule
{
public:
    EspModule() : CodecModule(CD_ESP_NAME, CD_ESP_HELP, esp_params) { }

    const RuleMap* get_rules() const override
    { return esp_rules; }

    bool set(const char*, Value& v, SnortConfig* sc) override
    {
        if ( v.is("decode_esp") )
            sc->enable_esp = v.get_bool();
        else
            return false;

        return true;
    }
};

class EspCodec : public Codec
{
public:
    EspCodec() : Codec(CD_ESP_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

/* ESP constants */
constexpr uint32_t ESP_HEADER_LEN = 8;
constexpr uint32_t ESP_AUTH_DATA_LEN = 12;
constexpr uint32_t ESP_TRAILER_LEN = 2;
} // anonymous namespace

void EspCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::ESP); }

/*
 * Attempt to decode Encapsulated Security Payload.
 * The contents are probably encrypted, but ESP is sometimes used
 * with "null" encryption, solely for Authentication.
 * This is more of a heuristic -- there is no ESP field that specifies
 * the encryption type (or lack thereof).
 */
bool EspCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    const uint8_t* esp_payload;
    uint8_t pad_length;
    uint8_t ip_proto;

    if (!SnortConfig::esp_decoding())
        return false;

    /* The ESP header contains a crypto Initialization Vector (IV) and
       a sequence number. Skip these. */
    if (raw.len < (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN))
    {
        /* Truncated ESP traffic. Bail out here and inspect the rest as payload. */
        codec_event(codec, DECODE_ESP_HEADER_TRUNC);
        return false;
    }

    /* The Authentication Data at the end of the packet is variable-length.
       RFC 2406 says that Encryption and Authentication algorithms MUST NOT
       both be NULL, so we assume NULL Encryption and some other Authentication.

       The mandatory algorithms for Authentication are HMAC-MD5-96 and
       HMAC-SHA-1-96, so we assume a 12-byte authentication data at the end. */
    uint32_t guessed_len = raw.len - (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN);

    codec.lyr_len = ESP_HEADER_LEN;
    esp_payload = raw.data + ESP_HEADER_LEN;
    pad_length = *(esp_payload + guessed_len);
    ip_proto = *(esp_payload + guessed_len + 1);
    codec.next_prot_id = (ProtocolId)ip_proto;

    // must be called AFTER setting next_prot_id
    if (snort.ip_api.is_ip6())
    {
        if ( SnortConfig::get_conf()->hit_ip6_maxopts(codec.ip6_extension_count) )
        {
            codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
            return false;
        }

        CheckIPv6ExtensionOrder(codec, IpProtocol::ESP);
        codec.proto_bits |= PROTO_BIT__IP6_EXT;
        codec.ip6_csum_proto = (IpProtocol)ip_proto;
        codec.ip6_extension_count++;
    }

    // FIXIT-L shouldn't this be raw.len = guessed_len ?
    const_cast<uint32_t&>(raw.len) -= (ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN);

    /* Adjust the packet length to account for the padding.
       If the padding length is too big, this is probably encrypted traffic. */
    if (pad_length < raw.len)
    {
        const_cast<uint32_t&>(raw.len) -= pad_length;
    }
    else
    {
        snort.decode_flags |= DECODE_PKT_TRUST;
        codec.lyr_len = ESP_HEADER_LEN;  // we want data to begin at (pkt + ESP_HEADER_LEN)
        codec.next_prot_id = ProtocolId::FINISHED_DECODE;
        return true;
    }

    /* Attempt to decode the inner payload.
       There is a small chance that an encrypted next_header would become a
       different valid next_header. The DECODE_UNSURE_ENCAP flag tells the next
       decoder stage to silently ignore invalid headers. */

    // highest valid protocol id == 255.

    //  FIXIT-L the next_prot_id will never be > 0xFF since it came from
    //  a uint8_t originally...
    if (to_utype(codec.next_prot_id) > 0xFF)
    {
        codec.next_prot_id = ProtocolId::FINISHED_DECODE;
        snort.decode_flags |= DECODE_PKT_TRUST;
    }
    else
    {
        codec.codec_flags |= CODEC_ENCAP_LAYER;
    }

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new EspModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new EspCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi esp_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_ESP_NAME,
        CD_ESP_HELP,
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
#else
const BaseApi* cd_esp[] =
#endif
{
    &esp_api.base,
    nullptr
};

