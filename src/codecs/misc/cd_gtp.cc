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
// cd_gtp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include "packet_io/active.h"

using namespace snort;

#define CD_GTP_NAME "gtp"
#define CD_GTP_HELP "support for general-packet-radio-service tunneling protocol"

namespace
{
static const RuleMap gtp_rules[] =
{
    { DECODE_GTP_MULTIPLE_ENCAPSULATION, "two or more GTP encapsulation layers present" },
    { DECODE_GTP_BAD_LEN, "GTP header length is invalid" },
    { 0, nullptr }
};

class GtpModule : public CodecModule
{
public:
    GtpModule() : CodecModule(CD_GTP_NAME, CD_GTP_HELP) { }

    const RuleMap* get_rules() const override
    { return gtp_rules; }
};

//-------------------------------------------------------------------------
// gtp module
//-------------------------------------------------------------------------

class GtpCodec : public Codec
{
public:
    GtpCodec() : Codec(CD_GTP_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
};

struct GTPHdr
{
    uint8_t flag;               /* flag: version (bit 6-8), PT (5), E (3), S (2), PN (1) */
    uint8_t type;
    uint16_t length;
};
} // anonymous namespace

static const uint32_t GTP_MIN_LEN = 8;
static const uint32_t GTP_V0_HEADER_LEN = 20;
static const uint32_t GTP_V1_HEADER_LEN = 12;

void GtpCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::GTP);
}

bool GtpCodec::decode(const RawData& raw, CodecData& codec, DecodeData& dd)
{
    uint8_t version;
    uint16_t len;

    const GTPHdr* const hdr = reinterpret_cast<const GTPHdr*>(raw.data);

    if (raw.len < GTP_MIN_LEN)
        return false;
    /* We only care about PDU*/
    if ( hdr->type != 255)
        return false;
    /*Check whether this is GTP or GTP', Exit if GTP'*/
    if (!(hdr->flag & 0x10))
        return false;

    /*The first 3 bits are version number*/
    version = (hdr->flag & 0xE0) >> 5;
    switch (version)
    {
    case 0: /*GTP v0*/
        len = GTP_V0_HEADER_LEN;
        if (raw.len < len)
        {
            codec_event(codec, DECODE_GTP_BAD_LEN);
            return false;
        }

        if (raw.len != ((unsigned int)ntohs(hdr->length) + len))
        {
            codec_event(codec, DECODE_GTP_BAD_LEN);
            return false;
        }

        break;
    case 1: /*GTP v1*/
        /*Check the length based on optional fields and extension header*/
        if (hdr->flag & 0x07)
        {
            len = GTP_V1_HEADER_LEN;

            /*Check optional fields*/
            if (raw.len < GTP_V1_HEADER_LEN)
            {
                codec_event(codec, DECODE_GTP_BAD_LEN);
                return false;
            }
            uint8_t next_hdr_type = *(raw.data + len - 1);

            /*Check extension headers*/
            while (next_hdr_type)
            {
                uint16_t ext_hdr_len;
                if (raw.len < (uint32_t)(len + 4))
                {
                    codec_event(codec, DECODE_GTP_BAD_LEN);
                    return false;
                }

                ext_hdr_len = *(raw.data + len);

                if (!ext_hdr_len)
                {
                    codec_event(codec, DECODE_GTP_BAD_LEN);
                    return false;
                }
                /*Extension header length is a unit of 4 octets*/
                len += ext_hdr_len * 4;

                if (raw.len < len)
                {
                    codec_event(codec, DECODE_GTP_BAD_LEN);
                    return false;
                }
                next_hdr_type = *(raw.data + len - 1);
            }
        }
        else
            len = GTP_MIN_LEN;

        if (raw.len != ((unsigned int)ntohs(hdr->length) + GTP_MIN_LEN))
        {
            codec_event(codec, DECODE_GTP_BAD_LEN);
            return false;
        }
        break;

    default:
        return false;
    }

    if ( SnortConfig::tunnel_bypass_enabled(TUNNEL_GTP) )
        Active::set_tunnel_bypass();

    codec.lyr_len = len;
    codec.proto_bits |= PROTO_BIT__GTP;

    if ( dd.decode_flags & DECODE_GTP )
        codec_event(codec, DECODE_GTP_MULTIPLE_ENCAPSULATION);
    else
        dd.decode_flags |= DECODE_GTP;

    if (raw.len > 0)
    {
        codec.codec_flags |= CODEC_ENCAP_LAYER;
        uint8_t ip_ver = *(raw.data + len) & 0xF0;

        if (ip_ver == 0x40)
            codec.next_prot_id = ProtocolId::IPIP;
        else if (ip_ver == 0x60)
            codec.next_prot_id = ProtocolId::IPV6;
    }
    codec.codec_flags |= CODEC_NON_IP_TUNNEL;

    return true;
}

/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/

static inline bool update_GTP_length(GTPHdr* const gtph, int gtp_total_len)
{
    /*The first 3 bits are version number*/
    const uint8_t version = (gtph->flag & 0xE0) >> 5;
    switch (version)
    {
    case 0: /*GTP v0*/
        gtph->length = htons((uint16_t)(gtp_total_len - GTP_V0_HEADER_LEN));
        break;
    case 1: /*GTP v1*/
        gtph->length = htons((uint16_t)(gtp_total_len - GTP_MIN_LEN));
        break;
    default:
        return false;
    }
    return false;
}

bool GtpCodec::encode(const uint8_t* const raw_in, const uint16_t raw_len,
    EncState&, Buffer& buf, Flow*)
{
    if (buf.allocate(raw_len))
        return false;

    GTPHdr* const gtph = reinterpret_cast<GTPHdr*>(buf.data());
    memcpy(gtph, raw_in, raw_len);
    return update_GTP_length(gtph, buf.size());
}

void GtpCodec::update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
    uint16_t lyr_len, uint32_t& updated_len)
{
    GTPHdr* const h = reinterpret_cast<GTPHdr*>(raw_pkt);
    updated_len += lyr_len;
    update_GTP_length(h, updated_len);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new GtpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new GtpCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi gtp_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_GTP_NAME,
        CD_GTP_HELP,
        mod_ctor,
        mod_dtor
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
const BaseApi* cd_gtp[] =
#endif
{
    &gtp_api.base,
    nullptr
};

