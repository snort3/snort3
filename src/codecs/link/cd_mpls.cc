//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// cd_mpls.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "flow/flow.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "utils/safec.h"

using namespace snort;

#define CD_MPLS_NAME "mpls"
#define CD_MPLS_HELP "support for multiprotocol label switching"

namespace
{
enum MplsPayloadType : uint8_t
{
    // Entries must align with payload_type enum parameter in mpls_params
    MPLS_PAYLOADTYPE_AUTODETECT = 0,
    MPLS_PAYLOADTYPE_ETHERNET,
    MPLS_PAYLOADTYPE_IPV4,
    MPLS_PAYLOADTYPE_IPV6
};

static const Parameter mpls_params[] =
{
    { "max_stack_depth", Parameter::PT_INT, "-1:255", "-1",
      "set maximum MPLS stack depth" },

    { "payload_type", Parameter::PT_ENUM, "auto | eth | ip4 | ip6", "auto",
      "force encapsulated payload type" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap mpls_rules[] =
{
    { DECODE_BAD_MPLS, "bad MPLS frame" },
    { DECODE_BAD_MPLS_LABEL0, "MPLS label 0 appears in bottom header when not decoding as ip4" },
    { DECODE_BAD_MPLS_LABEL1, "MPLS label 1 appears in bottom header" },
    { DECODE_BAD_MPLS_LABEL2, "MPLS label 2 appears in bottom header when not decoding as ip6" },
    { DECODE_BAD_MPLS_LABEL3, "MPLS label 3 appears in header" },
    { DECODE_MPLS_RESERVED_LABEL, "MPLS label 4, 5,.. or 15 appears in header" },
    { DECODE_MPLS_LABEL_STACK, "too many MPLS headers" },
    { 0, nullptr }
};

struct MplsCodecConfig
{
    int stack_depth = -1;
    uint8_t payload_type = MPLS_PAYLOADTYPE_AUTODETECT;
};

class MplsModule : public BaseCodecModule
{
public:
    MplsModule() : BaseCodecModule(CD_MPLS_NAME, CD_MPLS_HELP, mpls_params) { }

    const RuleMap* get_rules() const override
    { return mpls_rules; }

    bool begin(const char*, int, SnortConfig*) override
    {
        config = { };
        return true;
    }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        if ( v.is("max_stack_depth") )
            config.stack_depth = v.get_int16();
        else if ( v.is("payload_type") )
            config.payload_type = v.get_uint8();

        return true;
    }

    const MplsCodecConfig& get_data()
    { return config; }

private:
    MplsCodecConfig config;
};

class MplsCodec : public Codec
{
public:
    MplsCodec(const MplsCodecConfig& config = { }) : Codec(CD_MPLS_NAME), config(config) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;

private:
    bool validate_reserved_label(const CodecData&, uint32_t label, uint8_t bos);

private:
    MplsCodecConfig config;
};

constexpr int MPLS_HEADER_LEN = 4;
constexpr int NUM_RESERVED_LABELS = 16;
} // namespace

void MplsCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.emplace_back(ProtocolId::ETHERTYPE_MPLS_UNICAST);
    v.emplace_back(ProtocolId::ETHERTYPE_MPLS_MULTICAST);
    v.emplace_back(ProtocolId::MPLS_IP);
}

static inline void decode_mpls_entry(const uint32_t* entry, uint32_t& label, uint8_t& tc, uint8_t& bos, uint8_t& ttl)
{
    //                  https://tools.ietf.org/html/rfc5462
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Label
    // |                Label                  | TC  |S|       TTL     | Stack
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Entry
    //
    //                     Label:  Label Value, 20 bits
    //                     TC:     Traffic Class field, 3 bits
    //                     S:      Bottom of Stack, 1 bit
    //                     TTL:    Time to Live, 8 bits

    uint32_t mpls_h = ntohl(*entry);
    ttl = (uint8_t)(mpls_h & 0x000000FF);
    mpls_h = mpls_h >> 8;
    bos = (uint8_t)(mpls_h & 0x00000001);
    tc = (uint8_t)(mpls_h & 0x0000000E);
    label = (mpls_h >> 4) & 0x000FFFFF;
}

bool MplsCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    uint8_t bos = 0;
    uint8_t depth = 0;
    uint32_t stack_len = raw.len;

    const uint32_t* mpls_entry = reinterpret_cast<const uint32_t*>(raw.data);

    while (!bos)
    {
        if (stack_len < MPLS_HEADER_LEN)
        {
            codec_event(codec, DECODE_BAD_MPLS);
            return false;
        }

        uint32_t label;
        uint8_t tc;
        uint8_t ttl;

        decode_mpls_entry(mpls_entry, label, tc, bos, ttl);

        if ((label < NUM_RESERVED_LABELS) && !validate_reserved_label(codec, label, bos))
            return false;

        if (bos)
        {
            snort.mplsHdr.label = label;
            snort.mplsHdr.tc = tc;
            snort.mplsHdr.bos = bos;
            snort.mplsHdr.ttl = ttl;

            codec.proto_bits |= PROTO_BIT__MPLS;
        }
        mpls_entry++;
        stack_len -= MPLS_HEADER_LEN;

        if ((config.stack_depth != -1) && (++depth > config.stack_depth))
        {
            codec_event(codec, DECODE_MPLS_LABEL_STACK);

            codec.proto_bits &= ~PROTO_BIT__MPLS;
            return false;
        }
    }   /* peel off labels until we find the bottom of the stack */

    if (codec.conf->tunnel_bypass_enabled(TUNNEL_MPLS))
        codec.tunnel_bypass = true;

    codec.lyr_len = (const uint8_t*) mpls_entry - raw.data;

    uint8_t dplt = config.payload_type;
    if (snort.mplsHdr.label == 0)
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
    else if (snort.mplsHdr.label == 2)
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV6;
    else if (dplt == MPLS_PAYLOADTYPE_IPV4)
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
    else if (dplt == MPLS_PAYLOADTYPE_IPV6)
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV6;
    else if (dplt == MPLS_PAYLOADTYPE_ETHERNET)
        codec.next_prot_id = ProtocolId::ETHERTYPE_TRANS_ETHER_BRIDGING;
    else
    {
        // Default to first nibble autodetection
        //  This heuristic is obviously vulnerable to corner cases where the next layer is actually
        //  Ethernet and the first nibble of the destination MAC address is 4 or 6.
        if (codec.lyr_len == raw.len)
            return false;
        uint8_t first_nibble = (*(raw.data + codec.lyr_len) >> 4) & 0x0F;
        switch (first_nibble)
        {
            case 4:
                codec.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
                break;
            case 6:
                codec.next_prot_id = ProtocolId::ETHERTYPE_IPV6;
                break;
            default:
                codec.next_prot_id = ProtocolId::ETHERTYPE_TRANS_ETHER_BRIDGING;
                break;
        }
    }

    return true;
}

bool MplsCodec::encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState& enc, Buffer& buf, Flow* pflow)
{
    uint16_t hdr_len = raw_len;
    const uint8_t* hdr_start = raw_in;
    if (pflow)
    {
        Layer* mpls_lyr = pflow->get_mpls_layer_per_dir(enc.forward());

        if (mpls_lyr && mpls_lyr->length)
        {
            hdr_len = mpls_lyr->length;
            hdr_start = mpls_lyr->start;
            assert(hdr_start);
        }

    }

    if (!buf.allocate(hdr_len))
        return false;

    memcpy_s(buf.data(), hdr_len, hdr_start, hdr_len);
    enc.next_ethertype = ProtocolId::ETHERTYPE_NOT_SET;
    enc.next_proto = IpProtocol::PROTO_NOT_SET;

    return true;
}

/*
 * check if reserved labels are used properly
 */
bool MplsCodec::validate_reserved_label(const CodecData& codec, uint32_t label, uint8_t bos)
{
    uint8_t plt = config.payload_type;

    switch (label)
    {
        case 0:
            // Label 0 is the "IPv4 Explicit NULL Label", which indicates encapsulated IPv4 when at BoS
            //      RFC 3032 removed the BoS restriction for this label
            if (bos && plt && plt != MPLS_PAYLOADTYPE_IPV4)
                codec_event(codec, DECODE_BAD_MPLS_LABEL0);
            break;

        case 1:
            // Label 1 is the "Router Alert Label", which cannot occur at the bottom of the stack
            if (bos)
            {
                codec_event(codec, DECODE_BAD_MPLS_LABEL1);
                return false;
            }
            break;

        case 2:
            // Label 2 is the "IPv6 Explicit NULL Label", which indicates encapsulated IPv6 when at BoS
            //      RFC 3032 removed the BoS restriction for this label
            if (bos && plt && plt != MPLS_PAYLOADTYPE_IPV6)
                codec_event(codec, DECODE_BAD_MPLS_LABEL2);
            break;

        case 3:
            // Label 3 is the "Implicit NULL Label", which should never actually appear in a stack
            codec_event(codec, DECODE_BAD_MPLS_LABEL3);
            return false;

        default:
            // Labels 4-15 are reserved without any current special meaning
            codec_event(codec, DECODE_MPLS_RESERVED_LABEL);
            break;
    }

    return true;
}

void MplsCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const uint32_t* mpls_entry = reinterpret_cast<const uint32_t*>(raw_pkt);
    uint8_t bos = 0;
    while (!bos)
    {
        uint32_t label;
        uint8_t tc;
        uint8_t ttl;

        decode_mpls_entry(mpls_entry, label, tc, bos, ttl);
        TextLog_Print(text_log, "\n\tlabel:0x%05X tc:0x%hhX bos:0x%hhX ttl:0x%hhX", label, tc, bos, ttl);
        mpls_entry++;
    }
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new MplsModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module* m)
{
    if (m)
    {
        MplsModule* mod = (MplsModule*) m;
        return new MplsCodec(mod->get_data());
    }
    return new MplsCodec();
}

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi mpls_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_MPLS_NAME,
        CD_MPLS_HELP,
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
const BaseApi* cd_mpls[] =
#endif
{
    &mpls_api.base,
    nullptr
};

