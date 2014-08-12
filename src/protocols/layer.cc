/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2007-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// layer.cc author Josh Rosenbaum <jrosenba@cisco.com>


#include <netinet/in.h>
#include "protocols/packet.h"
#include "protocols/layer.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/ip.h"


namespace layer
{

static inline const uint8_t* find_outer_layer(const Layer* lyr,
                                uint8_t num_layers,
                                uint16_t prot_id)
{
    for(int i = 0; i < num_layers ; i++)
    {
        if (lyr->prot_id == prot_id)
            return lyr->start;
        lyr++;
    }
    return nullptr;
}

static inline const uint8_t* find_inner_layer(const Layer* lyr,
                                uint8_t num_layers,
                                uint16_t prot_id)
{
    int tmp = num_layers-1;
    lyr = &lyr[tmp];

    for(int i = tmp; i >= 0 ; i--)
    {
        if (lyr->prot_id == prot_id)
            return lyr->start;
        lyr--;
    }
    return nullptr;
}


static inline const uint8_t* find_inner_layer(const Layer* lyr,
                                uint8_t num_layers,
                                uint16_t prot_id1,
                                uint16_t prot_id2)
{
    int tmp = num_layers-1;
    lyr = &lyr[tmp];

    for(int i = num_layers - 1; i >= 0; i--)
    {
        if (lyr->prot_id == prot_id1 ||
            lyr->prot_id == prot_id2)
            return lyr->start;
        lyr--;
    }
    return nullptr;
}


const uint8_t* get_inner_layer(const Packet* p, uint16_t proto)
{ return find_inner_layer(p->layers, p->num_layers, proto); }


const uint8_t* get_outer_layer(const Packet* p, uint16_t proto)
{ return find_outer_layer(p->layers, p->num_layers, proto); }


const arp::EtherARP* get_arp_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer *lyr = p->layers;

    return reinterpret_cast<const arp::EtherARP*>(
        find_inner_layer(lyr, num_layers, ETHERTYPE_ARP, ETHERTYPE_REVARP));
}


const gre::GREHdr* get_gre_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    return reinterpret_cast<const gre::GREHdr*>(
        find_inner_layer(lyr, num_layers, IPPROTO_ID_GRE));
}


const eapol::EtherEapol* get_eapol_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    return reinterpret_cast<const eapol::EtherEapol*>(
        find_inner_layer(lyr, num_layers, ETHERTYPE_EAPOL));
}


const vlan::VlanTagHdr* get_vlan_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    return reinterpret_cast<const vlan::VlanTagHdr*>(
        find_inner_layer(lyr, num_layers, ETHERTYPE_8021Q));
}


const eth::EtherHdr* get_eth_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* lyr = p->layers;

    // First, search for the inner eth layer (transbridging)
    const eth::EtherHdr* eh = reinterpret_cast<const eth::EtherHdr*>(
        find_inner_layer(lyr, num_layers, ETHERTYPE_TRANS_ETHER_BRIDGING));

    // if no inner eth layer, assume root layer is eth (callers job to confirm)
    return eh ? eh : reinterpret_cast<const eth::EtherHdr*>(get_root_layer(p));
}


const udp::UDPHdr* get_outer_udp_lyr(const Packet* const p)
{
    return reinterpret_cast<const udp::UDPHdr*>(
        find_outer_layer(p->layers, p->num_layers, IPPROTO_UDP));
}


const uint8_t* get_root_layer(const Packet* const p)
{
    // since token ring is the grinder, its the begining of the packet.
    if (p->num_layers > 0)
        return p->layers[0].start;
    return nullptr;
}


uint8_t get_outer_ip_next_pro(const Packet* const p)
{
    const Layer* layers = p->layers;
    const int max_layers = p->num_layers;

    for (int i = 0; i < max_layers; i++)
    {
        switch(layers[i].prot_id)
        {
            case ETHERTYPE_IPV4:
            case IPPROTO_ID_IPIP:
                return reinterpret_cast<IP4Hdr*>(layers[i].start)->ip_proto;
            case ETHERTYPE_IPV6:
            case IPPROTO_ID_IPV6:
                return reinterpret_cast<ipv6::IP6RawHdr*>(layers[i].start)->get_next();
            default:
                break;
        }
    }
    return -1;
}

int get_inner_ip_lyr(const Packet* const p)
{
    const Layer* layers = p->layers;

    for (int i = p->num_layers-1; i >= 0; i--)
    {
        switch(layers[i].prot_id)
        {
            case ETHERTYPE_IPV4:
            case ETHERTYPE_IPV6:
            case IPPROTO_ID_IPIP:
            case IPPROTO_ID_IPV6:
                return i;
            default:
                break;
        }
    }
    return -1;
}

bool set_inner_ip_api(const Packet* const p,
                        ip::IpApi& api,
                        uint8_t& curr_layer)
{
    if (curr_layer >= p->num_layers)
        return false;

    do
    {
        const Layer* lyr = &p->layers[curr_layer];

        switch (lyr->prot_id)
        {
            case ETHERTYPE_IPV4:
            case IPPROTO_ID_IPIP:
            {
                const ip::IPHdr* ip4h =
                    reinterpret_cast<const ip::IPHdr*>(lyr->start);
                api.set(ip4h);
                return true;
            }
            case ETHERTYPE_IPV6:
            case IPPROTO_ID_IPV6:
            {
                const ipv6::IP6RawHdr* ip6h =
                    reinterpret_cast<const ipv6::IP6RawHdr*>(lyr->start);
                api.set(ip6h);
                return true;
            }
            //default:
                // don't care about this layer if its not IP.
        }

    } while (curr_layer-- != 0);

    return false;
}

bool set_outer_ip_api(const Packet* const p,
                      ip::IpApi& api,
                      uint8_t& curr_layer)
{
    uint8_t num_layers = p->num_layers;
    if (curr_layer >= num_layers)
        return false;

    do
    {
        const Layer* lyr = &p->layers[curr_layer];

        switch (lyr->prot_id)
        {
            case ETHERTYPE_IPV4:
            case IPPROTO_ID_IPIP:
            {
                const ip::IPHdr* ip4h =
                    reinterpret_cast<const ip::IPHdr*>(lyr->start);
                api.set(ip4h);
                return true;
            }
            case ETHERTYPE_IPV6:
            case IPPROTO_ID_IPV6:
            {
                const ipv6::IP6RawHdr* ip6h =
                    reinterpret_cast<const ipv6::IP6RawHdr*>(lyr->start);
                api.set(ip6h);
                return true;
            }
            //default:
                // don't care about this layer if its not IP.
        }

    } while (++curr_layer < num_layers);

    return false;
}




bool set_api_ip_embed_icmp(Packet* const p)
{ return set_api_ip_embed_icmp(p, p->ip_api); }

bool set_api_ip_embed_icmp(const Packet* p, ip::IpApi& api)
{
    int num_layers = p->num_layers - 1;
    const Layer* lyr = &p->layers[num_layers];

    for(int i = num_layers; i >= 0; i--)
    {
        if (lyr->prot_id == IP_EMBEDDED_IN_ICMP4)
        {
            const ip::IPHdr* ip4h =
                reinterpret_cast<const ip::IPHdr*>(lyr->start);
            api.set(ip4h);
            return true;
        }
        else if (lyr->prot_id == IP_EMBEDDED_IN_ICMP6)
        {
            const ipv6::IP6RawHdr* ip6h =
                reinterpret_cast<const ipv6::IP6RawHdr*>(lyr->start);
            api.set(ip6h);
            return true;
        }

        lyr--;
    }

    api.reset();
    return false;
}

const uint8_t* get_prot_embed_icmp(const Packet* const p)
{
    return find_inner_layer(p->layers,
                            p->num_layers,
                            PROT_EMBEDDED_IN_ICMP);
}

const tcp::TCPHdr* get_tcp_embed_icmp(const Packet* const p)
{
    return reinterpret_cast<const tcp::TCPHdr*>(
        get_prot_embed_icmp(p));
}

const udp::UDPHdr* get_udp_embed_icmp(const Packet* const p)
{
    return reinterpret_cast<const udp::UDPHdr*>(
        get_prot_embed_icmp(p));
}

const icmp::ICMPHdr* get_icmp_embed_icmp(const Packet* const p)
{
    return reinterpret_cast<const icmp::ICMPHdr*>(
        get_prot_embed_icmp(p));
}


} // namespace layer
