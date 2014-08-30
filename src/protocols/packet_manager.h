/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
// codec_manager.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef MANAGERS_PACKET_MANAGER_H
#define MANAGERS_PACKET_MANAGER_H

#include <array>
#include <list>

#include "main/snort_types.h"
#include "framework/codec.h"
#include "protocols/packet.h"
#include "framework/counts.h"
#include "managers/codec_manager.h"
#include "main/thread.h"


struct _daq_pkthdr;

/*
 *  PacketManager class
 */
class SO_PUBLIC PacketManager
{
public:

    // decode this packet and set all relevent packet fields.
    static void decode(Packet*, const struct _daq_pkthdr*, const uint8_t*);

    // allocate a Packet for later formatting (cloning)
    static Packet* encode_new(void);
    // release the allocated Packet
    static void encode_delete(Packet*);
    // update the packet's checksums and length variables. Call this function
    // after Snort has changed any data in this packet
    static void encode_update(Packet*);
    // format packet for detection.  Original ttl is always used.
    static int encode_format(
        EncodeFlags f, const Packet* orig, Packet* clone, PseudoPacketType type);
    // encode the packet with pre-set daq info.
    static int encode_format_with_daq_info (
        EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type,
        const DAQ_PktHdr_t*, uint32_t opaque);
    // orig is the wire pkt; clone was obtained with New()
    static const uint8_t* encode_response(
        EncodeType, EncodeFlags, const Packet* orig, uint32_t* len,
        const uint8_t* payLoad, uint32_t payLen);
    // when encoding, rather than copy the destination MAC address from the
    // inbound packet, manually set the MAC address.
    static void encode_set_dst_mac(uint8_t* );
    // get the MAC address which has been set using encode_set_dst_mac().
    // Useful for root decoders setting the MAC address
    static uint8_t *encode_get_dst_mac();

    // wrapper for encode response.  Ensure no payload is encoded.
    static inline const uint8_t* encode_reject( EncodeType type,
        EncodeFlags flags, const Packet* p, uint32_t* len)
    { return encode_response(type, flags, p, len, nullptr, 0); }

    // for backwards compatability and convenience.
    static inline int encode_format_with_daq_info (
        EncodeFlags f, const Packet* orig, Packet* clone,
        PseudoPacketType type, uint32_t opaque)
    { return encode_format_with_daq_info(f, orig, clone, type, nullptr, opaque); }


    /* codec support and statistics */


    // get the number of packets which have been rebuilt by this thread
    static PegCount get_rebuilt_packet_count(void);
    // check if a codec has been register for the specified protocol number
    static bool has_codec(uint16_t protocol);
    // set the packet to be encoded.
    static void encode_set_pkt(Packet* p);
    // reset the current 'clone' packet
    static inline void encode_reset(void)
    { encode_set_pkt(NULL); }


    // print codec information.  MUST be called after thread_term.
    static void dump_stats();
    // Get the name of the given protocol
    static const char* get_proto_name(uint16_t protocol);
    // Get the name of the given protocol
    static const char* get_proto_name(uint8_t protocol);

private:
    //  STATISTICS!!

    // The only time we should accumulate is when CodecManager tells us too
    friend void CodecManager::thread_term();
    static void accumulate();

    // constant offsets into the s_stats array.  Notice the stat_offset
    // constant which is used when adding a protocol specific codec
    static const uint8_t total_processed = 0;
    static const uint8_t other_codecs = 1;
    static const uint8_t discards = 2;
    static const uint8_t stat_offset = 3;

    // declared in header so it can access s_protocols
    static THREAD_LOCAL std::array<PegCount, stat_offset + CodecManager::s_protocols.size()> s_stats;
    static std::array<PegCount, s_stats.size()> g_stats;
    static const std::array<const char*, stat_offset> stat_names;
};

#endif
