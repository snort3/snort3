/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef LAYER_H 
#define LAYER_H

#include <cstdint>
#include "protocols/protocol_ids.h"
#include "codecs/sf_protocols.h"



struct Layer {
    uint16_t prot_id;
    PROTO_ID proto;
    uint16_t length;
    uint8_t* start;
};


// forward declaring relevent structs. Since we're only return a pointer,
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


namespace layer
{

// all of these functions will begin search from layer 0,
// and will return the first function they find.


const arp::EtherARP* get_arp_layer(const Packet*);
const vlan::VlanTagHdr* get_vlan_layer(const Packet*);
const gre::GREHdr* get_gre_layer(const Packet*);
const eapol::EtherEapol* get_eapol_layer(const Packet*);
const eth::EtherHdr* get_eth_layer(const Packet*);
const uint8_t* get_root_layer(const Packet* const);

int get_inner_ip_lyr(const Packet* const p);
uint16_t get_outer_ip_next_proto(const Packet* const);

} // namespace layer

#endif
