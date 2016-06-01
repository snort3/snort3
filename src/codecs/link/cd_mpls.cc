//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// cd_mpls.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "framework/codec.h"
#include "codecs/codec_module.h"
#include "protocols/mpls.h"
#include "packet_io/active.h"
#include "protocols/protocol_ids.h"
#include "protocols/mpls.h"
#include "main/snort_config.h"
#include "log/text_log.h"

#define CD_MPLS_NAME "mpls"
#define CD_MPLS_HELP "support for multiprotocol label switching"

namespace
{
static const Parameter mpls_params[] =
{
    { "enable_mpls_multicast", Parameter::PT_BOOL, nullptr, "false",
      "enables support for MPLS multicast" },

    { "enable_mpls_overlapping_ip", Parameter::PT_BOOL, nullptr, "false",
      "enable if private network addresses overlap and must be differentiated by MPLS label(s)" },

    { "max_mpls_stack_depth", Parameter::PT_INT, "-1:", "-1",
      "set MPLS stack depth" },

    { "mpls_payload_type", Parameter::PT_ENUM, "eth | ip4 | ip6", "ip4",
      "set encapsulated payload type" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

// rules which will loaded into snort.
// You can now reference these rules by calling a codec_event
// in your main codec's functions
static const RuleMap mpls_rules[] =
{
    { DECODE_BAD_MPLS, "bad MPLS frame" },
    { DECODE_BAD_MPLS_LABEL0, "MPLS label 0 appears in non-bottom header" },
    { DECODE_BAD_MPLS_LABEL1, "MPLS label 1 appears in bottom header" },
    { DECODE_BAD_MPLS_LABEL2, "MPLS label 2 appears in non-bottom header" },
    { DECODE_BAD_MPLS_LABEL3, "MPLS label 3 appears in header" },
    { DECODE_MPLS_RESERVED_LABEL, "MPLS label 4, 5,.. or 15 appears in header" },
    { DECODE_MPLS_LABEL_STACK, "too many MPLS headers" },
    { 0, nullptr }
};

static const PegInfo mpls_pegs[] =
{
    { "total packets", "total mpls labeled packets processed" },
    { "total bytes", "total mpls labeled bytes processed" },
    { nullptr, nullptr }
};

struct MplsStats
{
    PegCount total_packets;
    PegCount total_bytes;
};
static THREAD_LOCAL MplsStats mpls_stats;

class MplsModule : public CodecModule
{
public:
    MplsModule() : CodecModule(CD_MPLS_NAME, CD_MPLS_HELP, mpls_params) { }

    const RuleMap* get_rules() const override
    { return mpls_rules; }

    bool set(const char*, Value& v, SnortConfig* sc) override
    {
        if ( v.is("enable_mpls_multicast") )
        {
            if ( v.get_bool() )
                sc->run_flags |= RUN_FLAG__MPLS_MULTICAST; // FIXIT-L move to existing bitfield
        }
        else if ( v.is("enable_mpls_overlapping_ip") )
        {
            if ( v.get_bool() )
                sc->run_flags |= RUN_FLAG__MPLS_OVERLAPPING_IP; // FIXIT-L move to existing
                                                                // bitfield
        }
        else if ( v.is("max_mpls_stack_depth") )
        {
            sc->mpls_stack_depth = v.get_long();
        }
        else if ( v.is("mpls_payload_type") )
        {
            sc->mpls_payload_type = v.get_long() + 1;
        }
        else
            return false;

        return true;
    }

    virtual const PegInfo* get_pegs() const override
    { return mpls_pegs; }

    virtual PegCount* get_counts() const override
    { return (PegCount*)&mpls_stats; }
};

class MplsCodec : public Codec
{
public:
    MplsCodec() : Codec(CD_MPLS_NAME) { }
    ~MplsCodec() { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;

private:
    int checkMplsHdr(const CodecData&, uint32_t label, uint8_t bos);
};

constexpr int MPLS_HEADER_LEN = 4;
constexpr int NUM_RESERVED_LABELS = 16;
constexpr int MPLS_PAYLOADTYPE_ERROR = -1;
} // namespace

void MplsCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::ETHERTYPE_MPLS_UNICAST);
    v.push_back(ProtocolId::ETHERTYPE_MPLS_MULTICAST);
}

bool MplsCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    uint32_t mpls_h;
    uint32_t label;

    uint8_t exp;
    uint8_t bos = 0;
    uint8_t ttl;
    uint8_t chainLen = 0;
    uint32_t stack_len = raw.len;

    int iRet = 0;

    mpls_stats.total_packets++;
    mpls_stats.total_bytes += raw.len + 4; //4 bytes for CRC

    const uint32_t* tmpMplsHdr =
        reinterpret_cast<const uint32_t*>(raw.data);

    while (!bos)
    {
        if (stack_len < MPLS_HEADER_LEN)
        {
            codec_event(codec, DECODE_BAD_MPLS);
            return false;
        }

        mpls_h  = ntohl(*tmpMplsHdr);
        ttl = (uint8_t)(mpls_h & 0x000000FF);
        mpls_h = mpls_h>>8;
        bos = (uint8_t)(mpls_h & 0x00000001);
        exp = (uint8_t)(mpls_h & 0x0000000E);
        label = (mpls_h>>4) & 0x000FFFFF;

        if ((label<NUM_RESERVED_LABELS)&&((iRet = checkMplsHdr(codec, label, bos)) < 0))
            return false;

        if ( bos )
        {
            snort.mplsHdr.label = label;
            snort.mplsHdr.exp = exp;
            snort.mplsHdr.bos = bos;
            snort.mplsHdr.ttl = ttl;
            /**
            p->mpls = &(snort.mplsHdr);
      **/
            codec.proto_bits |= PROTO_BIT__MPLS;
            if (!iRet)
            {
                iRet = SnortConfig::get_mpls_payload_type();
            }
        }
        tmpMplsHdr++;
        stack_len -= MPLS_HEADER_LEN;

        if ((SnortConfig::get_mpls_stack_depth() != -1) &&
            (chainLen++ >= SnortConfig::get_mpls_stack_depth()))
        {
            codec_event(codec, DECODE_MPLS_LABEL_STACK);

            codec.proto_bits &= ~PROTO_BIT__MPLS;
            return false;
        }
    }   /* while bos not 1, peel off more labels */

    codec.lyr_len = (uint8_t*)tmpMplsHdr - raw.data;

    switch (iRet)
    {
    case MPLS_PAYLOADTYPE_IPV4:
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
        break;

    case MPLS_PAYLOADTYPE_IPV6:
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV6;
        break;

    case MPLS_PAYLOADTYPE_ETHERNET:
        codec.next_prot_id = ProtocolId::ETHERTYPE_TRANS_ETHER_BRIDGING;
        break;

    default:
        break;
    }

    return true;
}

/*
 * check if reserved labels are used properly
 */
int MplsCodec::checkMplsHdr(const CodecData& codec, uint32_t label, uint8_t bos)
{
    int iRet = 0;
    switch (label)
    {
    case 0:
    case 2:
        /* check if this label is the bottom of the stack */
        if (bos)
        {
            if ( label == 0 )
                iRet = MPLS_PAYLOADTYPE_IPV4;
            else if ( label == 2 )
                iRet = MPLS_PAYLOADTYPE_IPV6;

            /* when label == 2, IPv6 is expected;
             * when label == 0, IPv4 is expected */
            if ((label&&(SnortConfig::get_mpls_payload_type() != MPLS_PAYLOADTYPE_IPV6))
                ||((!label)&&(SnortConfig::get_mpls_payload_type() != MPLS_PAYLOADTYPE_IPV4)))
            {
                if ( !label )
                    codec_event(codec, DECODE_BAD_MPLS_LABEL0);
                else
                    codec_event(codec, DECODE_BAD_MPLS_LABEL2);
            }
            break;
        }

#if 0
        /* This is valid per RFC 4182.  Just pop this label off, ignore it
         * and move on to the next one.
         */
        if ( !label )
            codec_event(codec, DECODE_BAD_MPLS_LABEL0);
        else
            codec_event(codec, DECODE_BAD_MPLS_LABEL2);

        p->iph = NULL;
        p->family = NO_IP;
        return(-1);
#endif
        break;
    case 1:
        if (!bos)
            break;

        codec_event(codec, DECODE_BAD_MPLS_LABEL1);

        iRet = MPLS_PAYLOADTYPE_ERROR;
        break;

    case 3:
        codec_event(codec, DECODE_BAD_MPLS_LABEL3);

        iRet = MPLS_PAYLOADTYPE_ERROR;
        break;
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
        codec_event(codec, DECODE_MPLS_RESERVED_LABEL);
        break;
    default:
        break;
    }
    if ( !iRet )
    {
        iRet = SnortConfig::get_mpls_payload_type();
    }
    return iRet;
}

void MplsCodec::log(TextLog* const /*text_log*/, const uint8_t* /*raw_pkt*/,
    const uint16_t /*lyr_len*/)
{
// FIXIT-L  MPLS needs to be updated throughout Snort++
//  TextLog_Print(text_log,"label:0x%05X exp:0x%X bos:0x%X ttl:0x%X\n",
//      p->ptrs.mplsHdr.label, p->ptrs.mplsHdr.exp, p->ptrs.mplsHdr.bos, p->ptrs.mplsHdr.ttl);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new MplsModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new MplsCodec(); }

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
{
    &mpls_api.base,
    nullptr
};
#else
const BaseApi* cd_mpls = &mpls_api.base;
#endif

