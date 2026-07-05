//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
// layer.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "layer.h"

#include "packet.h"
#include "protocols/protocol_ids.h"
#include "protocols/udp.h"

namespace snort
{
namespace layer
{
static THREAD_LOCAL const Packet* curr_pkt;

static inline const uint8_t* find_outer_layer(const Layer* lyr,
    uint8_t num_layers,
    ProtocolId prot_id)
{
    for (int i = 0; i < num_layers; i++)
    {
        if (lyr->prot_id == prot_id)
            return lyr->start;
        lyr++;
    }
    return nullptr;
}

static inline const uint8_t* find_inner_layer(const Layer* lyr,
    uint8_t num_layers,
    ProtocolId prot_id)
{
    int tmp = num_layers-1;
    lyr = &lyr[tmp];

    for (int i = tmp; i >= 0; i--)
    {
        if (lyr->prot_id == prot_id)
            return lyr->start;
        lyr--;
    }
    return nullptr;
}

static inline const uint8_t* find_inner_layer(const Layer* lyr,
    uint8_t num_layers,
    ProtocolId prot_id1,
    ProtocolId prot_id2)
{
    int tmp = num_layers-1;
    lyr = &lyr[tmp];

    for (int i = num_layers - 1; i >= 0; i--)
    {
        if (lyr->prot_id == prot_id1 ||
            lyr->prot_id == prot_id2)
            return lyr->start;
        lyr--;
    }
    return nullptr;
}

static inline const Layer* find_layer(const Layer* lyr,
    uint8_t num_layers,
    ProtocolId prot_id1,
    ProtocolId prot_id2)
{
    int tmp = num_layers-1;
    lyr = &lyr[tmp];

    for (int i = num_layers - 1; i >= 0; i--)
    {
        if (lyr->prot_id == prot_id1 ||
            lyr->prot_id == prot_id2)
            return lyr;
        lyr--;
    }
    return nullptr;
}

void set_packet_pointer(const Packet* const p)
{ curr_pkt = p; }

const arp::EtherARP* get_arp_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    return reinterpret_cast<const arp::EtherARP*>(
        find_inner_layer(lyr, num_layers, ProtocolId::ETHERTYPE_ARP,
            ProtocolId::ETHERTYPE_REVARP));
}

const geneve::GeneveLyr* get_geneve_layer(const Packet* const p, bool inner)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    if (inner)
    {
        return reinterpret_cast<const geneve::GeneveLyr*>(
            find_inner_layer(lyr, num_layers, ProtocolId::GENEVE));
    }
    else
    {
        return reinterpret_cast<const geneve::GeneveLyr*>(
            find_outer_layer(lyr, num_layers, ProtocolId::GENEVE));
    }
}

const gre::GREHdr* get_gre_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    return reinterpret_cast<const gre::GREHdr*>(
        find_inner_layer(lyr, num_layers, ProtocolId::GRE));
}

const Layer* get_mpls_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    return find_layer(lyr, num_layers, ProtocolId::ETHERTYPE_MPLS_UNICAST,
            ProtocolId::ETHERTYPE_MPLS_MULTICAST);
}

const vlan::VlanTagHdr* get_vlan_layer(const Packet* const p)
{
    assert( p->proto_bits & PROTO_BIT__VLAN );
    assert( p->vlan_idx < p->num_layers );
    const Layer* lyr = p->layers + p->vlan_idx;
    return reinterpret_cast<const vlan::VlanTagHdr*>(lyr->start);
}

const vlan::VlanTagHdr* get_outer_vlan_layer(const Packet* const p)
{
    if ( !p->vlan_idx_outer )
        return nullptr;
    assert( p->vlan_idx_outer < p->num_layers );
    const Layer* lyr = p->layers + p->vlan_idx_outer;
    return reinterpret_cast<const vlan::VlanTagHdr*>(lyr->start);
}

const cisco_meta_data::CiscoMetaDataHdr* get_cisco_meta_data_layer(const Packet* const p)
{
    assert( p->proto_bits & PROTO_BIT__CISCO_META_DATA );

    const Layer* lyr = find_layer(p->layers, p->num_layers, ProtocolId::ETHERTYPE_CISCO_META,
        ProtocolId::ETHERTYPE_CISCO_META);

    return reinterpret_cast<const cisco_meta_data::CiscoMetaDataHdr*>(lyr->start);
}

const eth::EtherHdr* get_eth_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    // First, search for the inner eth layer (transbridging)
    const eth::EtherHdr* eh = reinterpret_cast<const eth::EtherHdr*>(
        find_inner_layer(lyr, num_layers, ProtocolId::ETHERTYPE_TRANS_ETHER_BRIDGING));

    // if no inner eth layer, assume root layer is eth (callers job to confirm)
    return eh ? eh : reinterpret_cast<const eth::EtherHdr*>(get_root_layer(p));
}

const wlan::WifiHdr* get_wifi_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    return reinterpret_cast<const wlan::WifiHdr*>(
        find_inner_layer(lyr, num_layers, ProtocolId::ETHERNET_802_11));
}

const ip::IP6Frag* get_inner_ip6_frag()
{ return get_inner_ip6_frag(curr_pkt); }

const ip::IP6Frag* get_inner_ip6_frag(const Packet* const pkt)
{
    // get_ip6h returns null if this is ipv4
    const ip::IP6Hdr* const ip6h = pkt->ptrs.ip_api.get_ip6h();

    if (ip6h)
    {
        const int max_layer = pkt->num_layers-1;
        const Layer* lyr = &(pkt->layers[max_layer]);

        for (int i = max_layer; i >= 0; i--)
        {
            if (lyr->prot_id == ProtocolId::FRAGMENT)
                return reinterpret_cast<const ip::IP6Frag*>(lyr->start);

            // Only check until current ip6h header
            if (lyr->start == (const uint8_t*)ip6h)
                return nullptr;

            lyr--;
        }
    }

    return nullptr;
}

int get_inner_ip6_frag_index(const Packet* const pkt)
{
    // get_ip6h returns null if this is ipv4
    const ip::IP6Hdr* const ip6h = pkt->ptrs.ip_api.get_ip6h();

    if (ip6h && curr_pkt->is_fragment())
    {
        const int max_layer = pkt->num_layers-1;
        const Layer* lyr = &(pkt->layers[max_layer]);

        for (int i = max_layer; i >= 0; i--)
        {
            if (lyr->prot_id == ProtocolId::FRAGMENT)
                return i;

            lyr--;
        }
    }
    return -1;
}

const udp::UDPHdr* get_outer_udp_lyr(const Packet* const p)
{
    return reinterpret_cast<const udp::UDPHdr*>(
        find_outer_layer(p->layers, p->num_layers, ProtocolId::UDP));
}

const uint8_t* get_root_layer(const Packet* const p)
{
    // since token ring is the grinder, its the beginning of the packet.
    if (p->num_layers > 0)
        return p->layers[0].start;
    return nullptr;
}

int get_inner_ip_lyr_index(const Packet* const p)
{
    const Layer* layers = p->layers;

    for (int i = p->num_layers-1; i >= 0; i--)
    {
        switch (layers[i].prot_id)
        {
        case ProtocolId::ETHERTYPE_IPV4:
        case ProtocolId::ETHERTYPE_IPV6:
        case ProtocolId::IPIP:
        case ProtocolId::IPV6:
            return i;
        default:
            break;
        }
    }
    return -1;
}

bool set_inner_ip_api(const Packet* const p,
    ip::IpApi& api,
    int8_t& curr_layer)
{
    IpProtocol tmp;
    return set_inner_ip_api(p, api, tmp, curr_layer);
}

bool set_inner_ip_api(const Packet* const p,
    ip::IpApi& api,
    IpProtocol& next_ip_proto,
    int8_t& curr_layer)
{
    if (curr_layer < 0 || curr_layer >= p->num_layers)
        return false;

    if (is_ip6_extension(p->layers[curr_layer].prot_id))
    {
        const ip::IP6Extension* const ip6_ext =
            reinterpret_cast<const ip::IP6Extension*>(p->layers[curr_layer].start);
        next_ip_proto = ip6_ext->ip6e_nxt;
        curr_layer--;
    }

    do
    {
        const Layer& lyr = p->layers[curr_layer];

        switch (lyr.prot_id)
        {
        case ProtocolId::ETHERTYPE_IPV4:
        case ProtocolId::IPIP:
        {
            const ip::IP4Hdr* ip4h =
                reinterpret_cast<const ip::IP4Hdr*>(lyr.start);
            api.set(ip4h);
            curr_layer--;
            return true;
        }

        case ProtocolId::ETHERTYPE_IPV6:
        case ProtocolId::IPV6:
        {
            const ip::IP6Hdr* ip6h =
                reinterpret_cast<const ip::IP6Hdr*>(lyr.start);
            api.set(ip6h);
            curr_layer--;
            return true;
        }

        case ProtocolId::HOPOPTS:
        case ProtocolId::DSTOPTS:
        case ProtocolId::ROUTING:
        case ProtocolId::FRAGMENT:
        case ProtocolId::AUTH:
        case ProtocolId::ESP:
        case ProtocolId::MOBILITY_IPV6:
        case ProtocolId::NONEXT:
            break;

        default:
            if(is_ip_protocol(lyr.prot_id))
                next_ip_proto = convert_protocolid_to_ipprotocol(lyr.prot_id);
        }
    }
    while (--curr_layer >= 0);

    return false;
}

bool set_outer_ip_api(const Packet* const p,
    ip::IpApi& api,
    IpProtocol& ip_proto_next,
    int8_t& curr_layer)
{
    if (set_outer_ip_api(p, api, curr_layer))
    {
        if (api.is_ip6())
        {
            const uint8_t num_layers = p->num_layers;

            while (curr_layer < num_layers &&
                is_ip6_extension(p->layers[curr_layer].prot_id))
            {
                curr_layer++;
            }

            // edge case.  Final layer is an IP6 extension.
            if (curr_layer >= num_layers  &&
                is_ip6_extension(p->layers[curr_layer].prot_id))
            {
                const ip::IP6Extension* const ip6_ext =
                    reinterpret_cast<const ip::IP6Extension*>(p->layers[curr_layer-1].start);
                ip_proto_next = ip6_ext->ip6e_nxt;
                return true;
            }
        }

        ip_proto_next = convert_protocolid_to_ipprotocol(p->layers[curr_layer].prot_id);
        return true;
    }

    return false;
}

bool set_outer_ip_api(const Packet* const p,
    ip::IpApi& api,
    int8_t& curr_layer)
{
    const uint8_t num_layers = p->num_layers;
    if (curr_layer < 0 || curr_layer >= num_layers)
        return false;

    do
    {
        const Layer& lyr = p->layers[curr_layer];

        switch (lyr.prot_id)
        {
        case ProtocolId::ETHERTYPE_IPV4:
        case ProtocolId::IPIP:
        {
            const ip::IP4Hdr* ip4h =
                reinterpret_cast<const ip::IP4Hdr*>(lyr.start);
            api.set(ip4h);
            curr_layer++;
            if(curr_layer >= num_layers)
                return false;
            return true;
        }
        case ProtocolId::ETHERTYPE_IPV6:
        case ProtocolId::IPV6:
        {
            const ip::IP6Hdr* ip6h =
                reinterpret_cast<const ip::IP6Hdr*>(lyr.start);
            api.set(ip6h);
            curr_layer++;
            if(curr_layer >= num_layers)
                return false;
            return true;
        }
        default:
            ; // don't care about this layer if its not IP.
        }
    }
    while (++curr_layer < num_layers);

    return false;
}

bool set_api_ip_embed_icmp(const Packet* p, ip::IpApi& api)
{
    int num_layers = p->num_layers - 1;

    for (int i = num_layers; i >= 0; --i)
    {
        const Layer& lyr = p->layers[i];

        if (lyr.prot_id == ProtocolId::IP_EMBEDDED_IN_ICMP4)
        {
            const ip::IP4Hdr* ip4h =
                reinterpret_cast<const ip::IP4Hdr*>(lyr.start);
            api.set(ip4h);
            return true;
        }
        else if (lyr.prot_id == ProtocolId::IP_EMBEDDED_IN_ICMP6)
        {
            const ip::IP6Hdr* ip6h =
                reinterpret_cast<const ip::IP6Hdr*>(lyr.start);
            api.set(ip6h);
            return true;
        }
    }

    api.reset();
    return false;
}

const tcp::TCPHdr* get_tcp_embed_icmp(const ip::IpApi& api)
{ return reinterpret_cast<const tcp::TCPHdr*>(api.ip_data()); }

const udp::UDPHdr* get_udp_embed_icmp(const ip::IpApi& api)
{ return reinterpret_cast<const udp::UDPHdr*>(api.ip_data()); }

const icmp::ICMPHdr* get_icmp_embed_icmp(const ip::IpApi& api)
{ return reinterpret_cast<const icmp::ICMPHdr*>(api.ip_data()); }

const char* get_tunnel_type_name(ProtocolId prot_id)
{
    switch (prot_id)
    {
    case ProtocolId::VXLAN:
        return "vxlan";
    case ProtocolId::GENEVE:
        return "geneve";
    case ProtocolId::GRE:
        return "gre";
    case ProtocolId::GTP:
        return "gtp";
    case ProtocolId::TEREDO:
        return "teredo";
    default:
        return "unknown";
    }
}

static inline bool is_tunnel_protocol(ProtocolId prot_id)
{
    switch (prot_id)
    {
    case ProtocolId::VXLAN:
    case ProtocolId::GENEVE:
    case ProtocolId::GRE:
    case ProtocolId::GTP:
    case ProtocolId::TEREDO:
        return true;
    default:
        return false;
    }
}

static inline bool tunnel_has_ports(ProtocolId prot_id)
{
    switch (prot_id)
    {
    case ProtocolId::VXLAN:
    case ProtocolId::GENEVE:
    case ProtocolId::GTP:
    case ProtocolId::TEREDO:
        return true;
    case ProtocolId::GRE:
    default:
        return false;
    }
}

static bool find_tunnel_outer_info(const Packet* p, int start_idx, TunnelInfo& info,
    const udp::UDPHdr*& pending_udp)
{
    ip::IpApi outer_ip_api;

    for (int j = start_idx; j >= 0; j--)
    {
        const Layer& lyr = p->layers[j];

        switch (lyr.prot_id)
        {
        case ProtocolId::ETHERTYPE_IPV4:
        case ProtocolId::IPIP:
        {
            const ip::IP4Hdr* ip4h = reinterpret_cast<const ip::IP4Hdr*>(lyr.start);
            outer_ip_api.set(ip4h);
            info.src_ip = *outer_ip_api.get_src();
            info.dst_ip = *outer_ip_api.get_dst();
            info.ip_proto = outer_ip_api.proto();
            return true;
        }
        case ProtocolId::ETHERTYPE_IPV6:
        case ProtocolId::IPV6:
        {
            const ip::IP6Hdr* ip6h = reinterpret_cast<const ip::IP6Hdr*>(lyr.start);
            outer_ip_api.set(ip6h);
            info.src_ip = *outer_ip_api.get_src();
            info.dst_ip = *outer_ip_api.get_dst();
            info.ip_proto = outer_ip_api.proto();
            return true;
        }
        case ProtocolId::UDP:
            pending_udp = reinterpret_cast<const udp::UDPHdr*>(lyr.start);
            break;
        default:
            break;
        }
    }
    return false;
}

std::vector<TunnelInfo> get_encapsulation_layers(const Packet* const p)
{
    std::vector<TunnelInfo> tunnels;

    if (!p || p->num_layers < 2)
        return tunnels;

    const int inner_ip_idx = get_inner_ip_lyr_index(p);
    if (inner_ip_idx < 0)
        return tunnels;

    const udp::UDPHdr* pending_udp = nullptr;

    for (int i = inner_ip_idx - 1; i >= 0; i--)
    {
        const Layer& lyr = p->layers[i];

        if (is_tunnel_protocol(lyr.prot_id))
        {
            TunnelInfo info;
            info.tunnel_type = lyr.prot_id;

            if (!find_tunnel_outer_info(p, i - 1, info, pending_udp))
            {
                // No outer IP found (truncated/partial decode) - skip this tunnel
                pending_udp = nullptr;
                continue;
            }

            info.has_ports = tunnel_has_ports(lyr.prot_id) && pending_udp;

            if (info.has_ports)
            {
                info.src_port = pending_udp->src_port();
                info.dst_port = pending_udp->dst_port();
            }

            tunnels.push_back(info);
            pending_udp = nullptr;
        }
    }

    return tunnels;
}

} // namespace layer
} // namespace snort
