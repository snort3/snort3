//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// cd_eapol.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "protocols/eapol.h"

#define CD_EAPOL_NAME "eapol"
#define CD_EAPOL_HELP "support for extensible authentication protocol over LAN"

namespace
{
static const RuleMap eapol_rules[] =
{
    { DECODE_EAPOL_TRUNCATED, "truncated EAP header" },
    { DECODE_EAPKEY_TRUNCATED, "EAP key truncated" },
    { DECODE_EAP_TRUNCATED, "EAP header truncated" },
    { 0, nullptr }
};

class EapolModule : public CodecModule
{
public:
    EapolModule() : CodecModule(CD_EAPOL_NAME, CD_EAPOL_HELP) { }

    const RuleMap* get_rules() const override
    { return eapol_rules; }
};

class EapolCodec : public Codec
{
public:
    EapolCodec() : Codec(CD_EAPOL_NAME) { }
    ~EapolCodec() { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_protocol_ids(std::vector<ProtocolId>&) override;

private:
    void DecodeEAP(const RawData&, const CodecData&);
    void DecodeEapolKey(const RawData&, const CodecData&);
};
} // namespace

void EapolCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::ETHERTYPE_EAPOL); }

void EapolCodec::DecodeEAP(const RawData& raw, const CodecData& codec)
{
    if (raw.len < sizeof(eapol::EAPHdr))
        codec_event(codec, DECODE_EAP_TRUNCATED);
}

void EapolCodec::DecodeEapolKey(const RawData& raw, const CodecData& codec)
{
    if (raw.len < sizeof(eapol::EapolKey))
        codec_event(codec, DECODE_EAPKEY_TRUNCATED);
}

/*************************************************
 ************** main codec functions  ************
 *************************************************/

bool EapolCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const eapol::EtherEapol* const eplh =
        reinterpret_cast<const eapol::EtherEapol*>(raw.data);

    if (raw.len < sizeof(eapol::EtherEapol))
    {
        codec_event(codec, DECODE_EAPOL_TRUNCATED);
        return false;
    }

    if (eplh->eaptype == EAPOL_TYPE_EAP)
        DecodeEAP(raw, codec);

    else if (eplh->eaptype == EAPOL_TYPE_KEY)
        DecodeEapolKey(raw, codec);

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new EapolModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new EapolCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi eapol_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_EAPOL_NAME,
        CD_EAPOL_HELP,
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

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &eapol_api.base,
    nullptr
};
