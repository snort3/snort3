//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
// token_ring.h author Josh Rosenbaum <jrosenba@cisco.com>

#include <sfbpf_dlt.h>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "protocols/token_ring.h"

namespace
{
#define TR_NAME "token_ring"
#define TR_HELP "support for token ring decoding"

static const RuleMap tkr_rules[] =
{
    { DECODE_BAD_TRH, "bad Token Ring header" },
    { DECODE_BAD_TR_ETHLLC, "bad Token Ring ETHLLC header" },
    { DECODE_BAD_TR_MR_LEN, "bad Token Ring MRLEN header" },
    { DECODE_BAD_TRHMR, "bad Token Ring MR header" },
    { 0, nullptr }
};

class TrCodecModule : public CodecModule
{
public:
    TrCodecModule() : CodecModule(TR_NAME, TR_HELP) { }

    const RuleMap* get_rules() const override
    { return tkr_rules; }
};

class TrCodec : public Codec
{
public:
    TrCodec() : Codec(TR_NAME) { }
    ~TrCodec() { }

    void get_data_link_type(std::vector<int>&) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

// THESE ARE NEVER USED!!
#define MINIMAL_TOKENRING_HEADER_LEN    22
#define TR_HLEN                         MINIMAL_TOKENRING_HEADER_LEN
#define TOKENRING_LLC_LEN                8
// DELETE FIN

#define TR_ALEN             6        /* octets in an Ethernet header */

#define AC                  0x10
#define LLC_FRAME           0x40

#define TRMTU                      2000    /* 2000 bytes            */
#define TR_RII                     0x80
#define TR_RCF_DIR_BIT             0x80
#define TR_RCF_LEN_MASK            0x1f00
#define TR_RCF_BROADCAST           0x8000    /* all-routes broadcast   */
#define TR_RCF_LIMITED_BROADCAST   0xC000    /* single-route broadcast */
#define TR_RCF_FRAME2K             0x20
#define TR_RCF_BROADCAST_MASK      0xC000
} // namespace

void TrCodec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_IEEE802);
}

//void DecodeTRPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
bool TrCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const uint32_t cap_len = raw.len;
    uint32_t dataoff;      /* data offset is variable here */

    if (cap_len < sizeof(token_ring::Trh_hdr))
    {
        codec_event(codec, DECODE_BAD_TRH);
        return false;
    }

    /* lay the tokenring header structure over the packet data */
    //const token_ring::Trh_hdr *trh = reinterpret_cast<const token_ring::Trh_hdr *>(raw_pkt);

    /*
     * according to rfc 1042:
     *
     *   The presence of a Routing Information Field is indicated by the Most
     *   Significant Bit (MSB) of the source address, called the Routing
     *   Information Indicator (RII).  If the RII equals zero, a RIF is
     *   not present.  If the RII equals 1, the RIF is present.
     *   ..
     *   However the MSB is already zeroed by this moment, so there's no
     *   real way to figure out whether RIF is presented in packet, so we are
     *   doing some tricks to find IPARP signature..
     */

    /*
     * first I assume that we have single-ring network with no RIF
     * information presented in frame
     */
    if (cap_len < (sizeof(token_ring::Trh_hdr) + sizeof(token_ring::Trh_llc)))
    {
        codec_event(codec, DECODE_BAD_TR_ETHLLC);
        return false;
    }

    const token_ring::Trh_llc* trhllc =
        reinterpret_cast<const token_ring::Trh_llc*>(raw.data + sizeof(token_ring::Trh_hdr));

    if (trhllc->dsap != IPARP_SAP && trhllc->ssap != IPARP_SAP)
    {
        /*
         * DSAP != SSAP != 0xAA .. either we are having frame which doesn't
         * carry IP datagrams or has RIF information present. We assume
         * the latter ...
         */

        if (cap_len < (sizeof(token_ring::Trh_hdr) + sizeof(token_ring::Trh_llc) +
            sizeof(token_ring::Trh_mr)))
        {
            codec_event(codec, DECODE_BAD_TRHMR);
            return false;
        }

        const token_ring::Trh_mr* const trhmr =
            reinterpret_cast<const token_ring::Trh_mr*>(raw.data + sizeof(token_ring::Trh_hdr));

        if (cap_len < (sizeof(token_ring::Trh_hdr) + sizeof(token_ring::Trh_llc) +
            sizeof(token_ring::Trh_mr) + TRH_MR_LEN(trhmr)))
        {
            codec_event(codec, DECODE_BAD_TR_MR_LEN);
            return false;
        }

        dataoff = sizeof(token_ring::Trh_hdr) + TRH_MR_LEN(trhmr) + sizeof(token_ring::Trh_llc);
    }
    else
    {
        dataoff = sizeof(token_ring::Trh_hdr) + sizeof(token_ring::Trh_llc);
    }

    /*
     * ideally we would need to check both SSAP, DSAP, and protoid fields: IP
     * datagrams and ARP requests and replies are transmitted in standard
     * 802.2 LLC Type 1 Unnumbered Information format, control code 3, with
     * the DSAP and the SSAP fields of the 802.2 header set to 170, the
     * assigned global SAP value for SNAP [6].  The 24-bit Organization Code
     * in the SNAP is zero, and the remaining 16 bits are the EtherType from
     * Assigned Numbers [7] (IP = 2048, ARP = 2054). .. but we would check
     * SSAP and DSAP and assume this would be enough to trust.
     */
    if (trhllc->dsap != IPARP_SAP && trhllc->ssap != IPARP_SAP)
    {
        return false;
    }

    codec.lyr_len = dataoff;
    codec.next_prot_id = trhllc->ethertype();
    codec.codec_flags |= CODEC_ETHER_NEXT;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TrCodecModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new TrCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi tr_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        TR_NAME,
        TR_HELP,
        mod_ctor,
        mod_dtor
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,
    dtor,
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &tr_api.base,
    nullptr
};

