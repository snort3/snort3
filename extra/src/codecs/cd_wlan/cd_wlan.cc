//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// cd_wlan.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sfbpf_dlt.h>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "protocols/wlan.h"

#define CD_WLAN_NAME "wlan"
#define CD_WLAN_HELP_STR "support for wireless local area network protocol"
#define CD_WLAN_HELP ADD_DLT(CD_WLAN_HELP_STR, DLT_IEEE802_11)

namespace
{
static const RuleMap wlan_rules[] =
{
    { DECODE_BAD_80211_ETHLLC, "bad 802.11 LLC header" },
    { DECODE_BAD_80211_OTHER, "bad 802.11 extra LLC info" },
    { 0, nullptr }
};

class WlanCodecModule : public CodecModule
{
public:
    WlanCodecModule() : CodecModule(CD_WLAN_NAME, CD_WLAN_HELP) { }

    const RuleMap* get_rules() const
    { return wlan_rules; }
};

class WlanCodec : public Codec
{
public:
    WlanCodec() : Codec(CD_WLAN_NAME) { }
    ~WlanCodec() { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_data_link_type(std::vector<int>&) override;
    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
};

#define MINIMAL_IEEE80211_HEADER_LEN    10    /* Ack frames and others */
#define IEEE802_11_DATA_HDR_LEN         24    /* Header for data packets */
} // namespace

void WlanCodec::get_data_link_type(std::vector<int>& v)
{ v.push_back(DLT_IEEE802_11); }

void WlanCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::ETHERNET_802_11); }

bool WlanCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < MINIMAL_IEEE80211_HEADER_LEN)
        return false;

    /* lay the wireless structure over the packet data */
    const wlan::WifiHdr* wifih = reinterpret_cast<const wlan::WifiHdr*>(raw.data);

    /* determine frame type */
    switch (wifih->frame_control & 0x00ff)
    {
    /* management frames */
    case WLAN_TYPE_MGMT_ASREQ:
    case WLAN_TYPE_MGMT_ASRES:
    case WLAN_TYPE_MGMT_REREQ:
    case WLAN_TYPE_MGMT_RERES:
    case WLAN_TYPE_MGMT_PRREQ:
    case WLAN_TYPE_MGMT_PRRES:
    case WLAN_TYPE_MGMT_BEACON:
    case WLAN_TYPE_MGMT_ATIM:
    case WLAN_TYPE_MGMT_DIS:
    case WLAN_TYPE_MGMT_AUTH:
    case WLAN_TYPE_MGMT_DEAUTH:
        break;

    /* Control frames */
    case WLAN_TYPE_CONT_PS:
    case WLAN_TYPE_CONT_RTS:
    case WLAN_TYPE_CONT_CTS:
    case WLAN_TYPE_CONT_ACK:
    case WLAN_TYPE_CONT_CFE:
    case WLAN_TYPE_CONT_CFACK:
        break;
    /* Data packets without data */
    case WLAN_TYPE_DATA_NULL:
    case WLAN_TYPE_DATA_CFACK:
    case WLAN_TYPE_DATA_CFPL:
    case WLAN_TYPE_DATA_ACKPL:

        break;
    case WLAN_TYPE_DATA_DTCFACK:
    case WLAN_TYPE_DATA_DTCFPL:
    case WLAN_TYPE_DATA_DTACKPL:
    case WLAN_TYPE_DATA_DATA:
    {
        codec.lyr_len = IEEE802_11_DATA_HDR_LEN;
        codec.next_prot_id = ProtocolId::ETHERNET_LLC;

        break;
    }
    default:
        break;
    }

    return true;
}

void WlanCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const wlan::WifiHdr* wifih = reinterpret_cast<const wlan::WifiHdr*>(raw_pkt);

    /* src addr */
    TextLog_Print(text_log, "addr1(%02X:%02X:%02X:%02X:%02X:%02X) -> ",
        wifih->addr1[0], wifih->addr1[1], wifih->addr1[2],
        wifih->addr1[3], wifih->addr1[4], wifih->addr1[5]);

    /* dest addr */
    TextLog_Print(text_log, "%02X:%02X:%02X:%02X:%02X:%02X)",
        wifih->addr2[0], wifih->addr2[1], wifih->addr2[2],
        wifih->addr2[3], wifih->addr2[4], wifih->addr2[5]);

    TextLog_NewLine(text_log);
    TextLog_Putc(text_log, '\t');
    TextLog_Print(text_log, "frame_control:%02x  duration_id:%02x  "
        "seq_control:%02x", ntohs(wifih->frame_control),
        ntohs(wifih->duration_id), ntohs(wifih->seq_control));
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new WlanCodecModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new WlanCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi wlan_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_WLAN_NAME,
        CD_WLAN_HELP,
        mod_ctor,
        mod_dtor
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ctor,
    dtor,
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &wlan_api.base,
    nullptr
};
