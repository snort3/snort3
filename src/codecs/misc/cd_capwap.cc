/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
// cd_capwap.cc author Josh Rosenbaum <jrosenba@cisco.com>




#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "framework/module.h"
#include "packet_io/active.h"
#include "snort_types.h"
#include "protocols/packet.h"
#include "snort.h"
#include "protocols/protocol_ids.h"
#include "codecs/codec_module.h"
#include "codecs/codec_events.h"

#define CD_CAPWAP_NAME "capwap"
#define CD_CAPWAP_HELP "support for capwap"

namespace
{

static const RuleMap capwap_rules[] =
{
    { DECODE_CAPWAP_TRUNC, "truncated CAPWAP header" },
    { 0, nullptr }
};

class CapwapModule : public CodecModule
{
public:
    CapwapModule() : CodecModule(CD_CAPWAP_NAME, CD_CAPWAP_HELP) {}

    const RuleMap* get_rules() const override
    { return capwap_rules; }
};


class CapwapCodec : public Codec
{
public:
    CapwapCodec() : Codec(CD_CAPWAP_NAME){};
    ~CapwapCodec(){};

    void get_protocol_ids(std::vector<uint16_t>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};


//  preamble_hlen_flags  flags
constexpr uint32_t MASK_PRE_VER    = 0xF0000000; // preamble version
constexpr uint32_t MASK_PRE_TYPE   = 0x0F000000; // preamble type
constexpr uint32_t MASK_HLEN       = 0x00F80000;
constexpr uint32_t MASK_RID        = 0x0007C000;
constexpr uint32_t MASK_WBID       = 0x00003E00;
constexpr uint32_t MASK_TYPE       = 0x00000100;
constexpr uint32_t MASK_FRAG       = 0x00000080;
constexpr uint32_t MASK_LAST       = 0x00000040;
constexpr uint32_t MASK_WIRELESS   = 0x00000020;
constexpr uint32_t MASK_RADIO_MAC  = 0x00000010;
constexpr uint32_t MASK_KEEP_ALIVE = 0x00000008;
constexpr uint32_t MASK_FLAGS      = 0x00000007;
//constexpr uint32_t MASK_ALL_FLAGS = ( MASK_TYPE | MASK_FRAG | MASK_LAST |
//    MASK_WIRELESS | MASK_RADIO_MAC | MASK_KEEP_ALIVE | MASK_FLAGS);  // currently unused

// frag_off flags
constexpr uint16_t MASK_FRAG_OFFSET = 0xFFF8;
constexpr uint16_t MASK_RESERVED    = 0x0007;

constexpr uint8_t WBID_IEEE_802_11 = 1;
// constexpr uint8_t WBID_EPCGLOBAL = 3;  // currently unused


constexpr uint16_t MIN_HDR_LEN = 8;
struct Capwap
{
    uint32_t preamble_hlen_flags;
    uint16_t frag_id;
    uint16_t frag_off; // last 3 bits are reserved.

    // returns the number of bytes in this header.
    uint8_t get_version() const
    { return (ntohl(preamble_hlen_flags) & MASK_PRE_VER) >> 28; }

    uint8_t get_preamble_type() const
    { return (ntohl(preamble_hlen_flags) & MASK_PRE_TYPE) >> 24; }

    uint8_t get_hlen() const
    { return (ntohl(preamble_hlen_flags) & MASK_HLEN) >> 17; }

    uint8_t get_rid() const
    { return (ntohl(preamble_hlen_flags) & MASK_RID) >> 14; }

    uint8_t get_wbid() const
    { return (ntohl(preamble_hlen_flags) & MASK_WBID) >> 9; }

    bool is_type_set() const
    { return ntohl(preamble_hlen_flags) & MASK_TYPE; }

    bool is_fragment() const
    { return ntohl(preamble_hlen_flags) & MASK_FRAG; }

    bool is_last_set() const
    { return ntohl(preamble_hlen_flags) & MASK_LAST; }

    bool is_wireless_set() const
    { return ntohl(preamble_hlen_flags) & MASK_WIRELESS; }

    bool is_radio_mac_set() const
    { return ntohl(preamble_hlen_flags) & MASK_RADIO_MAC; }

    bool is_keep_alive_set() const
    { return ntohl(preamble_hlen_flags) & MASK_KEEP_ALIVE; }

    uint8_t get_res_flags() const
    { return ntohl(preamble_hlen_flags) & MASK_FLAGS; }

    uint16_t get_frag_off() const
    { return ntohs(frag_off) & MASK_FRAG_OFFSET; }

    uint16_t get_reserved() const
    { return ntohs(frag_off) & MASK_RESERVED; }

};

struct RadioMacAddr
{
    uint8_t len;
    uint8_t mac[7]; // actual length is deteremined by len
};

struct WirelesInfo
{
    uint8_t len;
    uint8_t data[7]; // actual length is determined by len.
};

} // anonymous namespace


void CapwapCodec::get_protocol_ids(std::vector<uint16_t>& v)
{ v.push_back(PROTO_CAPWAP); }

bool CapwapCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if ( raw.len < MIN_HDR_LEN )
    {
        codec_events::decoder_event(codec, DECODE_CAPWAP_TRUNC);
        return false;
    }


    const Capwap* const capwaph = reinterpret_cast<const Capwap*>(raw.data);

    const uint8_t hlen = capwaph->get_hlen();
    if ( hlen < MIN_HDR_LEN )
    {
        codec_events::decoder_event(codec, DECODE_CAPWAP_TRUNC);
        return false;
    }

    if ( capwaph->get_version() != 0 )
        return false; // unsupported version

    if ( capwaph->get_preamble_type() != 0)
        return false; // don't support DTL

    if ( capwaph->is_fragment() )
        return false; // don't support fragments

    if ( !capwaph->is_type_set() )
    {
        codec.next_prot_id = PROTO_ETHERNET_802_3;
    }
    else
    {
        const uint8_t wbid = capwaph->get_wbid();

        if ( wbid == WBID_IEEE_802_11 )
            codec.next_prot_id = PROTO_ETHERNET_802_11;
        else
            return false; // don't support other protocols yet
    }

    codec.lyr_len = hlen;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new CapwapModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new CapwapCodec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi capwap_api =
{
    {
        PT_CODEC,
        CD_CAPWAP_NAME,
        CD_CAPWAP_HELP,
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
    &capwap_api.base,
    nullptr
};
#else
const BaseApi* cd_capwap = &capwap_api.base;
#endif
