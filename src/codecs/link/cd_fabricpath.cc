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
// cd_fabricpath.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"

using namespace snort;

#define CD_FABRICPATH_NAME "fabricpath"
#define CD_FABRICPATH_HELP "support for fabricpath"

namespace
{
static const RuleMap fabricpath_rules[] =
{
    { DECODE_FPATH_HDR_TRUNC, "truncated FabricPath header" },
    { 0, nullptr }
};

class FabricPathModule : public CodecModule
{
public:
    FabricPathModule() : CodecModule(CD_FABRICPATH_NAME, CD_FABRICPATH_HELP) { }

    const RuleMap* get_rules() const override
    { return fabricpath_rules; }
};

class FabricPathCodec : public Codec
{
public:
    FabricPathCodec() : Codec(CD_FABRICPATH_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;
};

struct FPathHdr
{
    uint8_t fpath_dst[6];
    uint8_t fpath_src[6];
    uint16_t fpath_type;
    uint16_t fptag_extra; /* 10-bit FTag + 6-bit TTL */
};

constexpr uint8_t FABRICPATH_HEADER_LEN = 16;
} // anonymous namespace

void FabricPathCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::ETHERTYPE_FPATH); }

bool FabricPathCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if ( raw.len < FABRICPATH_HEADER_LEN )
    {
        codec_event(codec, DECODE_FPATH_HDR_TRUNC);
        return false;
    }

    codec.next_prot_id = ProtocolId::ETHERNET_802_3;
    codec.lyr_len = FABRICPATH_HEADER_LEN;
    return true;
}

bool FabricPathCodec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
    EncState& enc, Buffer& buf, Flow*)
{
    // not raw ip -> encode layer 2
    bool raw = ( enc.flags & ENC_FLAG_RAW );

    if ( !raw )
    {
        if ( buf.size() == 0)
        {
            buf.off = 0;  // for alignment
        }
        else
        {
            // we get here for outer-most layer when not raw ip
            // we also get here for any encapsulated ethernet layer.
            if ( !buf.allocate(FABRICPATH_HEADER_LEN) )
                return true;

            const FPathHdr* hi = reinterpret_cast<const FPathHdr*>(raw_in);
            FPathHdr* ho = reinterpret_cast<FPathHdr*>(buf.data());

            ho->fpath_type = hi->fpath_type;
            if ( enc.forward() )
            {
                memcpy(ho->fpath_src, hi->fpath_src, sizeof(ho->fpath_src));
                memcpy(ho->fpath_dst, hi->fpath_dst, sizeof(ho->fpath_dst));
            }
            else
            {
                memcpy(ho->fpath_src, hi->fpath_dst, sizeof(ho->fpath_src));
                memcpy(ho->fpath_dst, hi->fpath_src, sizeof(ho->fpath_dst));
            }
        }
    }
    return true;
}

void FabricPathCodec::format(bool reverse, uint8_t* raw_pkt, DecodeData&)
{
    if ( reverse )
    {
        FPathHdr* ch = reinterpret_cast<FPathHdr*>(raw_pkt);
        uint8_t tmp_addr[6];

        memcpy(tmp_addr, ch->fpath_dst, sizeof(ch->fpath_dst));
        memcpy(ch->fpath_dst, ch->fpath_src, sizeof(ch->fpath_src));
        memcpy(ch->fpath_src, tmp_addr, sizeof(ch->fpath_src));
    }
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new FabricPathModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new FabricPathCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi fabricpath_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_FABRICPATH_NAME,
        CD_FABRICPATH_HELP,
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
const BaseApi* cd_fabricpath[] =
#endif
{
    &fabricpath_api.base,
    nullptr
};

