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
// packet_manager.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PACKET_MANAGER_H
#define PACKET_MANAGER_H

// PacketManager provides decode and encode services by leveraging Codecs.

#include <array>

#include "framework/codec.h"
#include "framework/counts.h"
#include "main/snort_types.h"
#include "managers/codec_manager.h"
#include "protocols/packet.h"

struct TextLog;

namespace snort
{
struct Packet;

enum class TcpResponse
{
    FIN,
    RST,
    PUSH,
};

enum class UnreachResponse
{
    NET,
    HOST,
    PORT,
    FWD,
};

// FIXIT-M roll the PacketManager and 'layer' namespace into the Packet
// struct

class SO_PUBLIC PacketManager
{
public:
    // decode this packet and set all relevant packet fields.
    static void decode(Packet*, const struct _daq_pkthdr*, const uint8_t*, bool cooked = false);

    // update the packet's checksums and length variables. Call this function
    // after Snort has changed any data in this packet
    static void encode_update(Packet*);

    //--------------------------------------------------------------------
    // FIXIT-L encode_format() should be replaced with a function that
    // does format and update in one step for packets cooked for internal
    // use only like stream_tcp and port_scan.  stream_ip packets should
    // just be decoded from last layer on.  at that point all the
    // Codec::format methods can be deleted too.  the new function should
    // be some super set of format_tcp().
    //--------------------------------------------------------------------

    // format packet for detection.  Original ttl is always used.  orig is
    // the wire pkt; clone was obtained with New()
    static int encode_format(
        EncodeFlags, const Packet* orig, Packet* clone,
        PseudoPacketType, const DAQ_PktHdr_t* = nullptr, uint32_t opaque = 0);

    static int format_tcp(
        EncodeFlags, const Packet* orig, Packet* clone, PseudoPacketType,
        const DAQ_PktHdr_t* = nullptr, uint32_t opaque = 0);

    // Send a TCP response.  TcpResponse params determined the type
    // of response. Len will be set to the response's length.
    // payload && payload_len are optional.
    static const uint8_t* encode_response(
        TcpResponse, EncodeFlags, const Packet* orig, uint32_t& len,
        const uint8_t* const payload = nullptr, uint32_t payload_len = 0);

    // Send an ICMP unreachable response!
    static const uint8_t* encode_reject(
        UnreachResponse, EncodeFlags, const Packet*, uint32_t& len);

    /* codec support and statistics */

    // get the number of packets which have been rebuilt by this thread
    static PegCount get_rebuilt_packet_count();

    // get the max payload for the current packet
    static uint16_t encode_get_max_payload(const Packet*);

    // print codec information.  MUST be called after thread_term.
    static void dump_stats();

    // Get the name of the given protocol ID
    static const char* get_proto_name(ProtocolId);

    // Get the name of the given IP protocol
    static const char* get_proto_name(IpProtocol);

    // print this packets information, layer by layer
    static void log_protocols(TextLog* const, const Packet* const);

    /* Accessor functions -- any object in Snort++ can now convert a
     * protocol to its mapped value.
     *
     * The equivalent of Snort's PROTO_ID */
    static constexpr std::size_t max_protocols() // compile time constant
    { return CodecManager::s_protocols.size(); }

    /* If a proto was registered in a Codec's get_protocol_ids() function,
     * this function will return the 'ProtocolIndex' of the Codec to which the proto belongs.
     * If none of the loaded Codecs registered that proto, this function will
     * return zero. */
    static ProtocolIndex proto_idx(ProtocolId prot_id)
    { return CodecManager::s_proto_map[to_utype(prot_id)]; }

private:
    // The only time we should accumulate is when CodecManager tells us too
    friend void CodecManager::thread_term();
    static void accumulate();
    static void pop_teredo(Packet*, RawData&);

    static bool encode(const Packet*, EncodeFlags,
        uint8_t lyr_start, IpProtocol next_prot, Buffer& buf);

    // constant offsets into the s_stats array.  Notice the stat_offset
    // constant which is used when adding a protocol specific codec
    static const uint8_t total_processed = 0;
    static const uint8_t other_codecs = 1;
    static const uint8_t discards = 2;
    static const uint8_t stat_offset = 3;

    // declared in header so it can access s_protocols
    static THREAD_LOCAL std::array<PegCount, stat_offset +
    CodecManager::s_protocols.size()> s_stats;
    // FIXIT-L gcc apparently does not consider thread_local variables to be valid in
    // constexpr expressions. As long as __thread is used instead of thread_local in gcc,
    // this is not a problem. However, if we use thread_local and gcc, the declaration
    // below will not compile.
    static std::array<PegCount, s_stats.size()> g_stats;
    static const std::array<const char*, stat_offset> stat_names;
};
}
#endif

