//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// packet.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet.h"

#include "detection/ips_context.h"
#include "flow/expect_flow.h"
#include "flow/flow_key.h"
#include "framework/endianness.h"
#include "log/obfuscator.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq_instance.h"

#include "packet_manager.h"
#include "vlan.h"
#include "geneve.h"

namespace snort
{
Packet::Packet(bool packet_data)
{
    layers = new Layer[PacketManager::get_max_layers()];
    allocated = packet_data;

    if (!packet_data)
    {
        pkt = nullptr;
        pkth = nullptr;
    }
    else
    {
        pkth = new DAQ_PktHdr_t();
        pkt = new uint8_t[Codec::PKT_MAX];
    }

    active_inst = new Active();
    reset();
}

Packet::~Packet()
{
    release_helpers();

    if (allocated)
    {
        delete pkth;
        delete[] pkt;
    }
    delete active_inst;
    delete[] layers;
}

void Packet::reset()
{
    flow = nullptr;
    packet_flags = 0;
    ts_packet_flags = 0;
    xtradata_mask = 0;
    proto_bits = 0;
    alt_dsize = 0;
    num_layers = 0;
    ip_proto_next = IpProtocol::PROTO_NOT_SET;
    disable_inspect = false;
    ExpectFlow::reset_expect_flows();

    release_helpers();
    ptrs.reset();

    user_inspection_policy_id = 0;
    user_ips_policy_id = 0;
    user_network_policy_id = 0;
    vlan_idx = 0;
    filtering_state.clear();
    sect = PS_NONE;
    inspection_started_timestamp = 0;
}

void Packet::release_helpers()
{
    if ( obfuscator )
    {
        delete obfuscator;
        obfuscator = nullptr;
    }

    if ( endianness )
    {
        delete endianness;
        endianness = nullptr;
    }
}

bool Packet::get_ip_proto_next(uint8_t& lyr, IpProtocol& proto) const
{
    if (lyr > num_layers)
        return false;

    while (lyr < num_layers)
    {
        switch (layers[lyr].prot_id)
        {
        case ProtocolId::IPV6:
        case ProtocolId::ETHERTYPE_IPV6:
            // move past this IP layer and any IPv6 extensions.
            while ( ((lyr + 1) < num_layers) && is_ip6_extension(layers[lyr+1].prot_id) )
                ++lyr;

            if ( (layers[lyr].prot_id == ProtocolId::IPV6) || (layers[lyr].prot_id ==
                ProtocolId::ETHERTYPE_IPV6) )
                proto =  reinterpret_cast<const ip::IP6Hdr*>(layers[lyr++].start)->next();
            else
                proto =  reinterpret_cast<const ip::IP6Extension*>(layers[lyr++].start)->ip6e_nxt;

            return true;

        case ProtocolId::ETHERTYPE_IPV4:
        case ProtocolId::IPIP:
            proto = reinterpret_cast<const ip::IP4Hdr*>(layers[lyr++].start)->proto();
            return true;

        default:
            ++lyr;
        }
    }

    return false;
}

const char* Packet::get_type() const
{
    switch ( ptrs.get_pkt_type() )
    {
    case PktType::IP:
        return "IP";

    case PktType::ICMP:
        return "ICMP";

    case PktType::TCP:
        return "TCP";

    case PktType::UDP:
        return "UDP";

    case PktType::PDU:
    case PktType::USER:
    case PktType::FILE:
        if ( proto_bits & PROTO_BIT__TCP )
            return "TCP";

        if ( proto_bits & PROTO_BIT__UDP )
            return "UDP";

        assert(false);
        return "Error";

    case PktType::NONE:
        if ( proto_bits & PROTO_BIT__ARP )
            return "ARP";

        if ( num_layers > 0 )
            return PacketManager::get_proto_name(layers[num_layers-1].prot_id);

        return "None";

    default:
        break;
    }
    assert(false);
    return "Error";
}

const char* Packet::get_pseudo_type() const
{
    if ( !(packet_flags & PKT_PSEUDO) )
        return "raw";

    switch ( pseudo_type )
    {
    case PSEUDO_PKT_IP:
        return "stream_ip";

    case PSEUDO_PKT_TCP:
        return "stream_tcp";

    case PSEUDO_PKT_USER:
        return "stream_user";

    case PSEUDO_PKT_DCE_SEG:
        return "dce2_rpc_deseg";

    case PSEUDO_PKT_DCE_FRAG:
        return "dce2_rpc_defrag";

    case PSEUDO_PKT_SMB_SEG:
        return "dce2_smb_deseg";

    case PSEUDO_PKT_SMB_TRANS:
        return "dce2_smb_transact";

    default: break;
    }
    return "other";
}

// Things that are set prior to PDU creation and used after PDU creation
static inline uint32_t get_session_flags(const Packet& p)
{
    if ( p.ptrs.get_pkt_type() == PktType::PDU )
        return p.context->get_session_flags();

    return p.flow ? p.flow->get_session_flags() : 0;
}

bool Packet::is_detection_enabled(bool to_server)
{
    uint32_t session_flags = get_session_flags(*this);

    if ( to_server )
        return !(session_flags & SSNFLAG_NO_DETECT_TO_SERVER);

    return !(session_flags & SSNFLAG_NO_DETECT_TO_CLIENT);
}

bool Packet::test_session_flags(uint32_t flags)
{ return (get_session_flags(*this) & flags) != 0; }

SnortProtocolId Packet::get_snort_protocol_id()
{
    if ( ptrs.get_pkt_type() == PktType::PDU )
        return context->get_snort_protocol_id();

    return flow ? flow->ssn_state.snort_protocol_id : UNKNOWN_PROTOCOL_ID;
}

uint16_t Packet::get_flow_vlan_id() const
{
    uint16_t vid = 0;

    if (flow)
        vid = flow->key->vlan_tag;
    else if ( !context->conf->get_vlan_agnostic() and (proto_bits & PROTO_BIT__VLAN) )
        vid = layer::get_vlan_layer(this)->vid();

    return vid;
}

uint32_t Packet::get_flow_geneve_vni() const
{
    uint32_t vni = 0;

    if (proto_bits & PROTO_BIT__GENEVE)
        vni = layer::get_geneve_layer(this, true)->hdr.vni();

    return vni;
}

std::vector<snort::geneve::GeneveOptData> Packet::get_geneve_options(bool inner) const
{
    const snort::geneve::GeneveLyr* lyr = layer::get_geneve_layer(this, inner);
    if (lyr)
        return lyr->get_opt_data();
    else
        return {};
}

uint16_t Packet::get_inner_pkt_offset() const
{
    uint16_t offset = 0;
    if (num_layers > 0 && proto_bits & PROTO_BIT__GENEVE)
    {
        for (int i = num_layers-1; i >= 0; i--)
        {
            if (layers[i].prot_id == ProtocolId::GENEVE)
            {
                offset = layers[i].start - layers[0].start + layers[i].length;
                break;
            }
        }
    }
    // TODO: Add support for other encapsulation types

    if (offset >= pktlen)
        return 0;

    return offset;
}

bool Packet::is_from_application_client() const
{
    if (flow)
        return flow->flags.app_direction_swapped ? is_from_server() : is_from_client();
    else
        return is_from_client();
}

bool Packet::is_from_application_server() const
{
    if (flow)
        return flow->flags.app_direction_swapped ? is_from_client() : is_from_server();
    else
        return is_from_server();
}

int Packet::inject()
{
    set_pkt_injected();
    return daq_instance->inject(daq_msg, 0, pkt, pktlen);
}

} // namespace snort

