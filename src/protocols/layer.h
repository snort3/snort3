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
// layer.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_LAYER_H
#define PROTOCOLS_LAYER_H

// Packet contains a Layer for each decoded encapsulation.

#include <vector>

#include "main/snort_types.h"
#include "protocols/protocol_ids.h"
#include "sfip/sf_ip.h"

namespace snort
{
struct Layer
{
    const uint8_t* start;
    ProtocolId prot_id;
    uint16_t length;
};

// forward declaring relevant structs. Since we're only returning a pointer,
// there is no need for the actual header files

namespace arp
{
struct EtherARP;
}

namespace cisco_meta_data
{
struct CiscoMetaDataHdr;
}

namespace eapol
{
struct EtherEapol;
}

namespace eth
{
struct EtherHdr;
}

namespace geneve
{
struct GeneveLyr;
}

namespace gre
{
struct GREHdr;
}

namespace icmp
{
struct ICMPHdr;
}

namespace ip
{
class IpApi;
struct IP6Frag;
}

namespace tcp
{
struct TCPHdr;
}

namespace udp
{
struct UDPHdr;
}

namespace vlan
{
struct VlanTagHdr;
}

namespace wlan
{
struct WifiHdr;
}

struct Packet;

// Encapsulation tunnel information for multi-layer visibility
struct TunnelInfo
{
    ProtocolId tunnel_type = ProtocolId::PROTO_NOT_SET;  // e.g., VXLAN, GRE, GTP, TEREDO, GENEVE
    SfIp src_ip{};                                        // outer IP source
    SfIp dst_ip{};                                        // outer IP destination
    uint16_t src_port = 0;                                // outer source port (0 if N/A)
    uint16_t dst_port = 0;                                // outer dest port (0 if N/A)
    IpProtocol ip_proto = IpProtocol::PROTO_NOT_SET;      // protocol number (e.g., 17 for UDP, 47 for GRE)
    bool has_ports = false;                               // true if tunnel uses ports (UDP-based)
};

namespace layer
{
//  Set by PacketManager.  Ensure you can call layer:: without a packet pointers
void set_packet_pointer(const Packet* const);

SO_PUBLIC const uint8_t* get_root_layer(const Packet* const);

SO_PUBLIC const arp::EtherARP* get_arp_layer(const Packet*);
SO_PUBLIC const cisco_meta_data::CiscoMetaDataHdr* get_cisco_meta_data_layer(const Packet* const);
SO_PUBLIC const eth::EtherHdr* get_eth_layer(const Packet*);
SO_PUBLIC const geneve::GeneveLyr* get_geneve_layer(const Packet*, bool inner);
SO_PUBLIC const gre::GREHdr* get_gre_layer(const Packet*);
SO_PUBLIC const vlan::VlanTagHdr* get_vlan_layer(const Packet*);
SO_PUBLIC const vlan::VlanTagHdr* get_outer_vlan_layer(const Packet*);
SO_PUBLIC const wlan::WifiHdr* get_wifi_layer(const Packet*);

/* return a pointer to the outermost UDP layer */
SO_PUBLIC const udp::UDPHdr* get_outer_udp_lyr(const Packet* const);
// return the inner ip layer's index in the p->layers array
SO_PUBLIC int get_inner_ip_lyr_index(const Packet* const);
SO_PUBLIC const Layer* get_mpls_layer(const Packet* const);

// Two versions of this because ip_defrag:: wants to call this on
// its rebuilt packet, not on the current packet.  Extra function
// header will be removed once layer is a part of the Packet struct
SO_PUBLIC const ip::IP6Frag* get_inner_ip6_frag();
SO_PUBLIC const ip::IP6Frag* get_inner_ip6_frag(const Packet* const);

// returns -1 on failure if no frag layer exists.
// else, returns zero based ip6 index
SO_PUBLIC int get_inner_ip6_frag_index(const Packet* const);

// ICMP with Embedded IP layer

// Sets the Packet's api to be the IP layer which is
// embedded inside an ICMP layer.
// RETURN:
//          true - ip layer found and api set
//          false - ip layer NOT found, api reset
SO_PUBLIC bool set_api_ip_embed_icmp(const Packet*, ip::IpApi& api);

/*
 *When a protocol is embedded in ICMP, these functions
 * will return a pointer to the layer.  Use the
 * proto_bits before calling these function to determine
 * what this layer is!
 */
SO_PUBLIC const tcp::TCPHdr* get_tcp_embed_icmp(const ip::IpApi&);
SO_PUBLIC const udp::UDPHdr* get_udp_embed_icmp(const ip::IpApi&);
SO_PUBLIC const icmp::ICMPHdr* get_icmp_embed_icmp(const ip::IpApi&);
/*
 * Starting from layer 'curr_layer', continuing looking at increasingly
 * outermost layer for another IP protocol.  If an IP protocol is found,
 * set the given ip_api to that layer.
 * PARAMS:
 *          Packet* = packet struct containing data
 *          ip::Api = ip api to be set
 *          uint8_t& next_ip_proto = The ip_protocol after the current IP
 *                              layer refer to packet get_next_ip_proto()
 *                              for more information.
 *          int8_t curr_layer = the current, zero based layer from which to
 *                              start searching inward. After the function returns,
 *                              This field will be set to the layer before
 *                              the Ip Api.  If no IP layer is found,
 *                              it will be set to -1.
 *
 *                               0 <= curr_layer < p->num_layers
 * RETURNS:
 *          true:  if the api is set
 *          false: if the api has NOT been set
 *
 * NOTE: curr_layer is zero based.  That means to get all of the ip
 *       layers (starting from the innermost layer), during the first call
 *       'curr_layer == p->num_layers'.
 *
 * NOTE: This functions is extremely useful in a loop
 *          while (set_inner_ip_api(p, api, layer)) { ... }
 */
SO_PUBLIC bool set_inner_ip_api(const Packet* const, ip::IpApi&, int8_t& curr_layer);
SO_PUBLIC bool set_inner_ip_api(const Packet* const, ip::IpApi&,
    IpProtocol& next_ip_proto, int8_t& curr_layer);

/*
 * Identical to above function except will begin searching from the
 * outermost layer until the innermost layer.
 *
 * NOTE: curr_layer is zero based.  That means to get all of the ip
 *       layers (starting from the OUTERMOST layer), during the first call
 *       'curr_layer == 0'.
 */
SO_PUBLIC bool set_outer_ip_api(const Packet* const, ip::IpApi&, int8_t& curr_layer);
SO_PUBLIC bool set_outer_ip_api(const Packet* const, ip::IpApi&,
    IpProtocol& next_ip_proto, int8_t& curr_layer);

// Multi-encapsulation visibility support
// Returns all encapsulation layers from innermost to outermost
// For a packet stack like: VXLAN -> GRE -> GTP -> TCP
// Returns: [GTP info, GRE info, VXLAN info] (innermost first)
std::vector<TunnelInfo> get_encapsulation_layers(const Packet* const);

// Returns the tunnel type name as a string (e.g., "vxlan", "gre", "gtp")
const char* get_tunnel_type_name(ProtocolId prot_id);

} // namespace layer
} // namespace snort
#endif

