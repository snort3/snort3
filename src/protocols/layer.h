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
// layer.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_LAYER_H
#define PROTOCOLS_LAYER_H

#include "main/snort_types.h"
#include "protocols/protocol_ids.h"

namespace snort
{
struct Layer
{
    const uint8_t* start;
    ProtocolId prot_id;
    uint16_t length;
};

// forward declaring relevant structs. Since we're only return a pointer,
// there is no need for the actual header files

namespace vlan
{
struct VlanTagHdr;
}

namespace arp
{
struct EtherARP;
}

namespace gre
{
struct GREHdr;
}

namespace eapol
{
struct EtherEapol;
}

namespace eth
{
struct EtherHdr;
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

namespace wlan
{
struct WifiHdr;
}

namespace icmp
{
struct ICMPHdr;
}

struct Packet;

namespace layer
{
//  Set by PacketManager.  Ensure you can call layer:: without a packet pointers
void set_packet_pointer(const Packet* const);

SO_PUBLIC const uint8_t* get_inner_layer(const Packet*, ProtocolId proto);
SO_PUBLIC const uint8_t* get_outer_layer(const Packet*, ProtocolId proto);

SO_PUBLIC const arp::EtherARP* get_arp_layer(const Packet*);
SO_PUBLIC const vlan::VlanTagHdr* get_vlan_layer(const Packet*);
SO_PUBLIC const gre::GREHdr* get_gre_layer(const Packet*);
SO_PUBLIC const eapol::EtherEapol* get_eapol_layer(const Packet*);
SO_PUBLIC const eth::EtherHdr* get_eth_layer(const Packet*);
SO_PUBLIC const wlan::WifiHdr* get_wifi_layer(const Packet*);
SO_PUBLIC const uint8_t* get_root_layer(const Packet* const);
/* return a pointer to the outermost UDP layer */
SO_PUBLIC const udp::UDPHdr* get_outer_udp_lyr(const Packet* const);
// return the inner ip layer's index in the p->layers array
SO_PUBLIC int get_inner_ip_lyr_index(const Packet* const p);
SO_PUBLIC const Layer* get_mpls_layer(const Packet* const p);

// Two versions of this because ip_defrag:: wants to call this on
// its rebuilt packet, not on the current packet.  Extra function
// header will be removed once layer is a part of the Packet struct
SO_PUBLIC const ip::IP6Frag* get_inner_ip6_frag();
SO_PUBLIC const ip::IP6Frag* get_inner_ip6_frag(const Packet* const p);

// returns -1 on failure if no frag layer exists.
// else, returns zero based ip6 index
SO_PUBLIC int get_inner_ip6_frag_index(const Packet* const p);

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
} // namespace layer
} // namespace snort
#endif

