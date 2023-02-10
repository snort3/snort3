//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// cd_geneve.cc author Raman S. Krishnan <ramanks@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "protocols/geneve.h"

using namespace snort;

#define CD_GENEVE_NAME "geneve"
#define CD_GENEVE_HELP "support for Geneve: Generic Network Virtualization Encapsulation"

#define RFC_8926_GENEVE_VERSION     0
#define GENEVE_ETH_TYPE             0x6558

#define GENEVE_FLAG_O               0x80
#define GENEVE_FLAG_C               0x40

#define GENEVE_OPT_TYPE_C           0x80

namespace
{
struct GeneveOpt
{
    uint16_t g_class;
    uint8_t  g_type;
    uint8_t  g_len;

    uint16_t optclass() const
    { return (ntohs(g_class)); }

    bool is_set(uint16_t which) const
    { return (g_type & which); }

    uint8_t type() const
    { return (g_type); }

    uint8_t olen() const
    { return (sizeof(GeneveOpt) + ((g_len & 0x1f) * 4)); }

    uint8_t len() const
    { return ((g_len & 0x1f) * 4); }
};

static const RuleMap geneve_rules[] =
{
    { DECODE_GENEVE_DGRAM_LT_GENEVE_HDR, "insufficient room for geneve header" },
    { DECODE_GENEVE_INVALID_VERSION, "invalid version" },
    { DECODE_GENEVE_INVALID_HEADER, "invalid header" },
    { DECODE_GENEVE_INVALID_FLAGS, "invalid flags" },
    { DECODE_GENEVE_INVALID_OPTIONS, "invalid options" },
    { 0, nullptr }
};

class GeneveModule : public BaseCodecModule
{
public:
    GeneveModule() : BaseCodecModule(CD_GENEVE_NAME, CD_GENEVE_HELP) { }

    const RuleMap* get_rules() const override
    { return geneve_rules; }
};

class GeneveCodec : public Codec
{
public:
    GeneveCodec() : Codec(CD_GENEVE_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;

private:

    void log_opts(TextLog* const, const uint8_t*, const uint16_t len);
    bool validate_options(const uint8_t* rptr, uint16_t optlen, CodecData& codec);
};

} // namespace

void GeneveCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::GENEVE);
}

bool GeneveCodec::validate_options(const uint8_t* rptr, uint16_t hdrlen, CodecData& codec)
{
    const geneve::GeneveHdr* const hdr = reinterpret_cast<const geneve::GeneveHdr*>(rptr);
    uint16_t offset = sizeof(geneve::GeneveHdr);
    uint16_t copts = 0;

    /* Skip past tunnel header */
    rptr += sizeof(geneve::GeneveHdr);

    while (offset < hdrlen)
    {
        const GeneveOpt* const opt = reinterpret_cast<const GeneveOpt*>(rptr);
        uint8_t olen = opt->olen();

        if ((offset + olen) > hdrlen)
        {
            codec_event(codec, DECODE_GENEVE_INVALID_OPTIONS);
            return false;
        }

        if (opt->is_set(GENEVE_OPT_TYPE_C))
            copts++;

        rptr += olen;
        offset += olen;
    }

    /*
     * Generate event if
     *   C flag is clear but critical options are present
     *   C flag is set   but critical options are absent
     */
    if ((!copts && hdr->is_set(GENEVE_FLAG_C)) || (copts && !hdr->is_set(GENEVE_FLAG_C)))
    {
        codec_event(codec, DECODE_GENEVE_INVALID_FLAGS);
        return false;
    }

    return true;
}

bool GeneveCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if ( raw.len < sizeof(geneve::GeneveHdr) )
    {
        codec_event(codec, DECODE_GENEVE_DGRAM_LT_GENEVE_HDR);
        return false;
    }

    const geneve::GeneveHdr* const hdr = reinterpret_cast<const geneve::GeneveHdr*>(raw.data);

    if (hdr->version() != RFC_8926_GENEVE_VERSION)
    {
        codec_event(codec, DECODE_GENEVE_INVALID_VERSION);
        return false;
    }

    const uint16_t optlen = hdr->optlen();
    const uint32_t hdrlen = hdr->hlen();
    if (raw.len <  hdrlen)
    {
        codec_event(codec, DECODE_GENEVE_INVALID_HEADER);
        return false;
    }

    /* If critical header present bit is set, optlen cannot be 0 */
    if (hdr->is_set(GENEVE_FLAG_C) && (optlen == 0))
    {
        codec_event(codec, DECODE_GENEVE_INVALID_FLAGS);
        return false;
    }

    if (!validate_options(raw.data, hdrlen, codec))
    {
        return false;
    }

    if ( codec.conf->tunnel_bypass_enabled(TUNNEL_GENEVE) )
        codec.tunnel_bypass = true;

    uint16_t next = hdr->proto();
    ProtocolId proto = (next == GENEVE_ETH_TYPE) ? ProtocolId::ETHERNET_802_3 : (ProtocolId) next;

    codec.lyr_len = hdrlen;
    codec.proto_bits |= PROTO_BIT__GENEVE;
    codec.next_prot_id = proto;
    codec.codec_flags |= CODEC_NON_IP_TUNNEL;

    return true;
}

void GeneveCodec::log_opts(TextLog* const text_log, const uint8_t *rptr, uint16_t optlen)
{
    uint16_t offset = 0;

    while (offset < optlen)
    {
        const GeneveOpt* const opt = reinterpret_cast<const GeneveOpt*>(rptr);
        uint8_t olen = opt->olen();

        TextLog_Print(text_log, "\n\tclass 0x%04x, type 0x%02x%s, len %3u%s", opt->optclass(),
            opt->type(), (opt->is_set(GENEVE_OPT_TYPE_C) ? " (C)" : ""), olen, (olen ? " value " : ""));

        rptr += sizeof(GeneveOpt);

        for (int idx=0; idx < opt->len(); idx++)
            TextLog_Print(text_log, "%02x ", *rptr++);

        offset += olen;
    }
}

void GeneveCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const uint8_t* rptr = raw_pkt;
    const geneve::GeneveHdr* const hdr = reinterpret_cast<const geneve::GeneveHdr*>(rptr);
    rptr += sizeof(geneve::GeneveHdr);

    std::string flags = "";

    if (hdr->is_set(GENEVE_FLAG_O))
        flags += "O";

    if (hdr->is_set(GENEVE_FLAG_C))
        flags += "C";

    if (flags == "")
        flags = "none";

    TextLog_Print(text_log, "version %u, optlen %u flags [%s]", hdr->version(), hdr->optlen(), flags.c_str());
    TextLog_Print(text_log, " network id %u, next protocol: 0x%04x", hdr->vni(), hdr->proto());

    log_opts(text_log, rptr, hdr->optlen());
}

bool GeneveCodec::encode(const uint8_t* const raw_in, const uint16_t raw_len,
    EncState&, Buffer& buf, Flow*)
{
    if (!buf.allocate(raw_len))
        return false;

    geneve::GeneveHdr* const hdr = reinterpret_cast<geneve::GeneveHdr*>(buf.data());
    memcpy(hdr, raw_in, raw_len);
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new GeneveModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new GeneveCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi geneve_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_GENEVE_NAME,
        CD_GENEVE_HELP,
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
const BaseApi* cd_geneve[] =
#endif
{
    &geneve_api.base,
    nullptr
};

