//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// cd_auth.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"

using namespace snort;

#define CD_AUTH_NAME "auth"
#define CD_AUTH_HELP "support for IP authentication header"

namespace
{
static const RuleMap auth_rules[] =
{
    { DECODE_AUTH_HDR_TRUNC, "truncated authentication header" },
    { DECODE_AUTH_HDR_BAD_LEN, "bad authentication header length" },
    { 0, nullptr }
};

class AuthModule : public CodecModule
{
public:
    AuthModule() : CodecModule(CD_AUTH_NAME, CD_AUTH_HELP) { }

    const RuleMap* get_rules() const override
    { return auth_rules; }
};

//-------------------------------------------------------------------------
// auth module
//-------------------------------------------------------------------------

class AuthCodec : public Codec
{
public:
    AuthCodec() : Codec(CD_AUTH_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

/*  Valid for both IPv4 and IPv6 */
struct AuthHdr
{
    IpProtocol next;
    uint8_t len;
    uint16_t rsv;   /* reserved */
    uint32_t spi;   /* Security Parameters Index */
    uint32_t seq;   /* Sequence Number */
    uint32_t icv[1]; /* VARIABLE LENGTH!! -- specified by len field*/
};

constexpr uint8_t MIN_AUTH_LEN = 16; // this is in minimum number of bytes ...
// no relation to the AuthHdr.len field.
} // anonymous namespace

void AuthCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::AUTH); }

bool AuthCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    const AuthHdr* const ah = reinterpret_cast<const AuthHdr*>(raw.data);

    if (raw.len < MIN_AUTH_LEN)
    {
        codec_event(codec, DECODE_AUTH_HDR_TRUNC);
        return false;
    }

    // 8 is the number of bytes excluded in the length. Check out IPv6 Options length
    // fields for a better explanation
    codec.lyr_len = 8 + (ah->len << 2);

    if (codec.lyr_len > raw.len)
    {
        codec_event(codec, DECODE_AUTH_HDR_BAD_LEN);
        return false;
    }

    codec.next_prot_id = (ProtocolId)ah->next;

    // must be called AFTER setting next_prot_id
    if (snort.ip_api.is_ip6())
    {
        if ( SnortConfig::get_conf()->hit_ip6_maxopts(codec.ip6_extension_count) )
        {
            codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
            return false;
        }

        CheckIPv6ExtensionOrder(codec, IpProtocol::AUTH);
        codec.proto_bits |= PROTO_BIT__IP6_EXT;
        codec.ip6_csum_proto = ah->next;
        codec.ip6_extension_count++;
    }
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new AuthModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new AuthCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ah_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_AUTH_NAME,
        CD_AUTH_HELP,
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
const BaseApi* cd_ah[] =
#endif
{
    &ah_api.base,
    nullptr
};

