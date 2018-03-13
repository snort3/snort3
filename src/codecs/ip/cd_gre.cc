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
// cd_gre.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "protocols/gre.h"

using namespace snort;

#define CD_GRE_NAME "gre"
#define CD_GRE_HELP "support for generic routing encapsulation"

namespace
{
static const RuleMap gre_rules[] =
{
    { DECODE_GRE_DGRAM_LT_GREHDR, "GRE header length > payload length" },
    { DECODE_GRE_MULTIPLE_ENCAPSULATION, "multiple encapsulations in packet" },
    { DECODE_GRE_INVALID_VERSION, "invalid GRE version" },
    { DECODE_GRE_INVALID_HEADER, "invalid GRE header" },
    { DECODE_GRE_V1_INVALID_HEADER, "invalid GRE v.1 PPTP header" },
    { DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR, "GRE trans header length > payload length" },
    { 0, nullptr }
};

class GreModule : public CodecModule
{
public:
    GreModule() : CodecModule(CD_GRE_NAME, CD_GRE_HELP) { }

    const RuleMap* get_rules() const override
    { return gre_rules; }
};

class GreCodec : public Codec
{
public:
    GreCodec() : Codec(CD_GRE_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
};

static const uint32_t GRE_HEADER_LEN = 4;
static const uint32_t GRE_CHKSUM_LEN = 2;
static const uint32_t GRE_OFFSET_LEN = 2;
static const uint32_t GRE_KEY_LEN = 4;
static const uint32_t GRE_SEQ_LEN = 4;
static const uint32_t GRE_SRE_HEADER_LEN = 4;

/* GRE version 1 used with PPTP
   static const uint32_t GRE_V1_HEADER_LEN == GRE_HEADER_LEN + GRE_KEY_LEN; */
static const uint32_t GRE_V1_ACK_LEN = 4;

#define GRE_V1_FLAGS(x)   ((x)->version & 0x78)
#define GRE_V1_ACK(x)     ((x)->version & 0x80)
#define GRE_CHKSUM(x)  ((x)->flags & 0x80)
#define GRE_ROUTE(x)   ((x)->flags & 0x40)
#define GRE_KEY(x)     ((x)->flags & 0x20)
#define GRE_SEQ(x)     ((x)->flags & 0x10)
#define GRE_SSR(x)     ((x)->flags & 0x08)
#define GRE_RECUR(x)   ((x)->flags & 0x07)
#define GRE_FLAGS(x)   ((x)->version & 0xF8)
} // anonymous namespace

void GreCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::GRE); }

/*
 * see RFCs 1701, 2784 and 2637
 */
bool GreCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < GRE_HEADER_LEN)
    {
        codec_event(codec, DECODE_GRE_DGRAM_LT_GREHDR);
        return false;
    }

    /* Note: Since GRE doesn't have a field to indicate header length and
     * can contain a few options, we need to walk through the header to
     * figure out the length
     */

    const gre::GREHdr* const greh = reinterpret_cast<const gre::GREHdr*>(raw.data);
    uint16_t len = GRE_HEADER_LEN;

    switch (greh->get_version())
    {
    case 0x00:
        /* these must not be set */
        if (GRE_RECUR(greh) || GRE_FLAGS(greh))
        {
            codec_event(codec, DECODE_GRE_INVALID_HEADER);
            return false;
        }

        if (GRE_CHKSUM(greh) || GRE_ROUTE(greh))
            len += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;

        if (GRE_KEY(greh))
            len += GRE_KEY_LEN;

        if (GRE_SEQ(greh))
            len += GRE_SEQ_LEN;

        /* if this flag is set, we need to walk through all of the
         * Source Route Entries */
        if (GRE_ROUTE(greh))
        {
            const uint8_t* sre_ptr = raw.data + len;

            while (true)
            {
                len += GRE_SRE_HEADER_LEN;

                if (len > raw.len)
                    break;

                uint16_t sre_addrfamily = ntohs(*((const uint16_t*)sre_ptr));

                sre_ptr += sizeof(sre_addrfamily);
                sre_ptr += sizeof(uint8_t);  // sre_offset

                uint8_t sre_length = *((const uint8_t*)sre_ptr);
                sre_ptr += sizeof(sre_length);

                if ((sre_addrfamily == 0) && (sre_length == 0))
                    break;

                len += sre_length;
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
            codec_event(codec, DECODE_GRE_V1_INVALID_HEADER);
            return false;
        }

        /* protocol must be 0x880B - PPP */
        if (greh->proto() != ProtocolId::ETHERTYPE_PPP)
        {
            codec_event(codec, DECODE_GRE_V1_INVALID_HEADER);
            return false;
        }

        /* this flag should always be present */
        if (!(GRE_KEY(greh)))
        {
            codec_event(codec, DECODE_GRE_V1_INVALID_HEADER);
            return false;
        }

        len += GRE_KEY_LEN;

        if (GRE_SEQ(greh))
            len += GRE_SEQ_LEN;

        if (GRE_V1_ACK(greh))
            len += GRE_V1_ACK_LEN;

        break;

    default:
        codec_event(codec, DECODE_GRE_INVALID_VERSION);
        return false;
    }

    if (len > raw.len)
    {
        codec_event(codec, DECODE_GRE_DGRAM_LT_GREHDR);
        return false;
    }

    if (SnortConfig::tunnel_bypass_enabled(TUNNEL_GRE))
        Active::set_tunnel_bypass();

    codec.lyr_len = len;
    codec.next_prot_id = greh->proto();
    codec.codec_flags |= CODEC_NON_IP_TUNNEL | CODEC_ETHER_NEXT;
    return true;
}

void GreCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const gre::GREHdr* greh = reinterpret_cast<const gre::GREHdr*>(raw_pkt);

    TextLog_Print(text_log, "version:%u flags:0x%02X ethertype:(0x%04X)",
        greh->get_version(), greh->flags,
        greh->proto());
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new GreModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new GreCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi gre_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_GRE_NAME,
        CD_GRE_HELP,
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
const BaseApi* cd_gre[] =
#endif
{
    &gre_api.base,
    nullptr
};

