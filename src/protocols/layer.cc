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


#include "protocols/packet.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"

namespace layer
{

static inline const uint8_t *find_layer(const Layer *lyr,
                                uint8_t num_layers,
                                uint16_t prot_id)
{
    for(int i = num_layers - 1; i >= 0 ; i--)
    {
        if (lyr->prot_id == prot_id)
            return lyr->start;
        lyr++;
    }
    return nullptr;
}

static inline const uint8_t *find_layer(const Layer *lyr,
                                uint8_t num_layers,
                                uint16_t prot_id1,
                                uint16_t prot_id2)
{
    for(int i = num_layers - 1; i >= 0; i--)
    {
        if (lyr->prot_id == prot_id1 ||
            lyr->prot_id == prot_id2)
            return lyr->start;
        lyr++;
    }
    return nullptr;
}

const arp::EtherARP* get_arp_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer *lyr = p->layers;

    return reinterpret_cast<const arp::EtherARP*>(
        find_layer(lyr, num_layers, ETHERTYPE_ARP, ETHERTYPE_REVARP));
}

const gre::GREHdr* get_gre_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer *lyr = p->layers;

    return reinterpret_cast<const gre::GREHdr*>(
        find_layer(lyr, num_layers, IPPROTO_ID_GRE));
}

const eapol::EtherEapol* get_eapol_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer *lyr = p->layers;

    return reinterpret_cast<const eapol::EtherEapol*>(
            find_layer(lyr, num_layers, ETHERTYPE_EAPOL));
}

const vlan::VlanTagHdr* get_vlan_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer *lyr = p->layers;

    return reinterpret_cast<const vlan::VlanTagHdr*>(
        find_layer(lyr, num_layers, ETHERTYPE_8021Q));
}

const eth::EtherHdr* get_eth_layer(const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer *lyr = p->layers;

    // First, search for the inner eth layer (transbridging)
    const eth::EtherHdr* eh = reinterpret_cast<const eth::EtherHdr*>(
        find_layer(lyr, num_layers, ETHERTYPE_TRANS_ETHER_BRIDGING));

    // if no inner eth layer, assume root layer is eth (callers job to confirm)
    return eh ? eh : reinterpret_cast<const eth::EtherHdr*>(get_root_layer(p));
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
                return reinterpret_cast<IP6Hdr*>(layers[i].start)->next;
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

} // namespace layer
