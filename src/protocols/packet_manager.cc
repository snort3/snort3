//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// packet_manager.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_manager.h"

#include <daq.h>
#include <mutex>

#include "codecs/codec_module.h"
#include "codecs/ip/checksum.h"
#include "detection/detection_engine.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "profiler/profiler_defs.h"
#include "stream/stream.h"
#include "trace/trace_api.h"

#include "eth.h"
#include "icmp4.h"
#include "icmp6.h"

using namespace snort;

THREAD_LOCAL ProfileStats decodePerfStats;

// Decoding statistics

// this may be my longer member declaration ... ever
THREAD_LOCAL std::array<PegCount,PacketManager::stat_offset +
CodecManager::s_protocols.size()> PacketManager::s_stats {
    { 0 }
};

//PacketManager::s_stats{{0}};
std::array<PegCount, PacketManager::s_stats.size()> PacketManager::g_stats;

// names which will be printed for the first three statistics
// in s_stats/g_stats
const std::array<const char*, PacketManager::stat_offset> PacketManager::stat_names =
{
    {
        "total",
        "other",
        "discards",
        "depth_exceeded"
    }
};

// Encoder Foo
static THREAD_LOCAL std::array<uint8_t, Codec::PKT_MAX>* s_pkt;

void PacketManager::thread_init()
{
    s_pkt = new std::array<uint8_t, Codec::PKT_MAX>{ {0} };
}

void PacketManager::thread_term()
{
    delete s_pkt;
}

//-------------------------------------------------------------------------
// Private helper functions
//-------------------------------------------------------------------------

inline bool PacketManager::push_layer(Packet* p, CodecData& codec_data, ProtocolId prot_id,
    const uint8_t* hdr_start, uint32_t len)
{
    if ( p->num_layers == CodecManager::get_max_layers() )
    {
        if (!(codec_data.codec_flags & CODEC_LAYERS_EXCEEDED))
        {
            codec_data.codec_flags |= CODEC_LAYERS_EXCEEDED;
            DetectionEngine::queue_event(GID_DECODE, DECODE_TOO_MANY_LAYERS);
            s_stats[depth_exceeded]++;
        }
        return false;
    }

    Layer& lyr = p->layers[p->num_layers++];
    lyr.prot_id = prot_id;
    lyr.start = hdr_start;
    lyr.length = (uint16_t)len;
//    lyr.invalid_bits = p->byte_skip;  -- currently unused

    return true;
}

inline Codec* PacketManager::get_layer_codec(const Layer& lyr, int idx)
{
    ProtocolIndex mapped_prot;
    // prot_id == ProtocolId::FINISHED_DECODE is a special case for root codecs not registering a protocol ID
    if (idx == 0 && (lyr.prot_id == CodecManager::grinder_id || lyr.prot_id == ProtocolId::FINISHED_DECODE))
        mapped_prot = CodecManager::grinder;
    else
        mapped_prot = CodecManager::s_proto_map[to_utype(lyr.prot_id)];
    return CodecManager::s_protocols[mapped_prot];
}

void PacketManager::pop_teredo(Packet* p, RawData& raw)
{
    p->proto_bits &= ~PROTO_BIT__TEREDO;
    if ( p->context->conf->tunnel_bypass_enabled(TUNNEL_TEREDO) )
        p->active->clear_tunnel_bypass();

    const ProtocolIndex mapped_prot = CodecManager::s_proto_map[to_utype(ProtocolId::TEREDO)];
    s_stats[mapped_prot + stat_offset]--;
    p->num_layers--;

    const Layer& lyr = p->layers[p->num_layers];
    const uint16_t lyr_len = raw.data - lyr.start;
    raw.data = lyr.start;
    raw.len += lyr_len;
}

void PacketManager::handle_decode_failure(Packet* p, RawData& raw, const CodecData& codec_data,
    const DecodeData& unsure_encap_ptrs, ProtocolId prev_prot_id)
{
    if (codec_data.codec_flags & CODEC_UNSURE_ENCAP)
    {
        p->ptrs = unsure_encap_ptrs;

        switch (p->layers[p->num_layers - 1].prot_id)
        {
            case ProtocolId::ESP:
                // Hardcoding ESP because we trust iff the layer
                // immediately preceding the fail is ESP.
                p->ptrs.decode_flags |= DECODE_PKT_TRUST;
                break;

            case ProtocolId::TEREDO:
                // if we just decoded teredo and the next
                // layer fails, we made a mistake. Therefore,
                // remove this bit.
                pop_teredo(p, raw);
                break;
            default:
                break;
        }
        return;
    }

    if ( (p->num_layers > 0) && (p->layers[p->num_layers - 1].prot_id == ProtocolId::TEREDO) &&
        (prev_prot_id == ProtocolId::IPV6) )
    {
        pop_teredo(p, raw);
    }

    // if the codec exists, it failed
    if (CodecManager::s_proto_map[to_utype(prev_prot_id)])
    {
        s_stats[discards]++;
    }
    else
    {
        s_stats[other_codecs]++;

        if ( (to_utype(ProtocolId::MIN_UNASSIGNED_IP_PROTO) <= to_utype(prev_prot_id)) &&
                (to_utype(prev_prot_id) <= std::numeric_limits<uint8_t>::max()) )
        {
            DetectionEngine::queue_event(GID_DECODE, DECODE_IP_UNASSIGNED_PROTO);
        }
    }
}

static inline bool payload_offset_from_daq_mismatch(const uint8_t* pkt, const RawData& raw)
{
    const DAQ_PktDecodeData_t* pdd =
        (const DAQ_PktDecodeData_t*) daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_DECODE_DATA);
    if ( !pdd || (pdd->payload_offset == DAQ_PKT_DECODE_OFFSET_INVALID) )
        return false;
    // compare payload offset from DAQ with decoded data offset
    if ( raw.data - pkt != pdd->payload_offset )
        return true;
    return false;
}

//-------------------------------------------------------------------------
// Initialization and setup
//-------------------------------------------------------------------------

// Assertions required for this code to work

//  Look below inside main decode() loop for these static_asserts
static_assert(CODEC_ENCAP_LAYER == (CODEC_UNSURE_ENCAP | CODEC_SAVE_LAYER),
    "If this is an encapsulated layer, you must also set UNSURE_ENCAP"
    " and SAVE_LAYER");

//-------------------------------------------------------------------------
// Encode/Decode functions
//-------------------------------------------------------------------------
void PacketManager::decode(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt, uint32_t pktlen, bool cooked, bool retry)
{
    Profile profile(decodePerfStats);

    DecodeData unsure_encap_ptrs;

    ProtocolIndex mapped_prot = CodecManager::grinder;
    ProtocolId prev_prot_id = CodecManager::grinder_id;

    RawData raw(p->daq_msg, pkt, pktlen);
    CodecData codec_data(p->context->conf, ProtocolId::FINISHED_DECODE);

    if (cooked)
        codec_data.codec_flags |= CODEC_STREAM_REBUILT;

    // initialize all Packet information
    p->reset();
    p->pkth = pkthdr;
    p->pkt = pkt;
    p->pktlen = pktlen;
    if (retry)
        p->packet_flags |= PKT_RETRY;
    layer::set_packet_pointer(p);

    s_stats[total_processed]++;

    // loop until the protocol id is no longer valid
    while (CodecManager::s_protocols[mapped_prot]->decode(raw, codec_data, p->ptrs))
    {
        debug_logf(decode_trace, nullptr,
            "Codec %s (0x%0*hx) starts at %u, length is %hu\n",
            CodecManager::s_protocols[mapped_prot]->get_name(),
            (static_cast<uint16_t>(prev_prot_id) < 0xFF) ? 2 : 4,
            static_cast<uint16_t>(prev_prot_id),
            pktlen - raw.len, codec_data.lyr_len);

        if (codec_data.codec_flags & CODEC_COMPOUND)
        {
            for (int idx = 0; idx < codec_data.compound_layer_cnt; idx++)
            {
                CompoundLayer* clyr = &codec_data.compound_layers[idx];

                // If this was an IP layer, stash the next protocol in the Packet for later
                if (clyr->proto_bits & (PROTO_BIT__IP | PROTO_BIT__IP6_EXT) &&
                    idx + 1 < codec_data.compound_layer_cnt)
                {
                    CompoundLayer* nclyr = &codec_data.compound_layers[idx + 1];
                    p->ip_proto_next = convert_protocolid_to_ipprotocol(nclyr->layer.prot_id);
                }
                p->proto_bits |= clyr->proto_bits;

                // If we have reached the MAX_LAYERS, we keep decoding
                // but no longer keep track of the layers.
                if (!push_layer(p, codec_data, clyr->layer.prot_id, clyr->layer.start, clyr->layer.length))
                    continue;

                // Cache the index of the vlan layer for quick access.
                if (clyr->proto_bits == PROTO_BIT__VLAN)
                    p->vlan_idx = p->num_layers - 1;
            }
            codec_data.codec_flags &= ~CODEC_COMPOUND;
        }
        else
        {
            // If this was an IP layer, stash the next protocol in the Packet for later
            if (codec_data.proto_bits & (PROTO_BIT__IP | PROTO_BIT__IP6_EXT))
            {
                // FIXIT-M refactor when ip_proto's become an array
                if (p->is_fragment())
                {
                    if (prev_prot_id == ProtocolId::FRAGMENT)
                    {
                        const ip::IP6Frag* const fragh = reinterpret_cast<const ip::IP6Frag*>(raw.data);
                        p->ip_proto_next = fragh->next();
                    }
                    else
                        p->ip_proto_next = p->ptrs.ip_api.get_ip4h()->proto();
                }
                else
                {
                    if (codec_data.next_prot_id != ProtocolId::FINISHED_DECODE)
                        p->ip_proto_next = convert_protocolid_to_ipprotocol(codec_data.next_prot_id);
                }
            }

            // If we have reached the MAX_LAYERS, we keep decoding
            // but no longer keep track of the layers.
            if (push_layer(p, codec_data, prev_prot_id, raw.data, codec_data.lyr_len))
            {
                // Cache the index of the vlan layer for quick access.
                if (codec_data.proto_bits == PROTO_BIT__VLAN)
                    p->vlan_idx = p->num_layers - 1;
            }
        }

        if (codec_data.tunnel_bypass)
        {
            p->active->set_tunnel_bypass();
            codec_data.tunnel_bypass = false;
        }

        // Sanity check the next protocol ID is a valid ethertype
        if (codec_data.codec_flags & CODEC_ETHER_NEXT)
        {
            if (codec_data.next_prot_id < ProtocolId::ETHERTYPE_MINIMUM)
            {
                DetectionEngine::queue_event(GID_DECODE, DECODE_BAD_ETHER_TYPE);
                break;
            }
            codec_data.codec_flags &= ~CODEC_ETHER_NEXT;
        }

        /*
         * We only want the layer immediately following SAVE_LAYER to have the
         * UNSURE_ENCAP flag set.  So, if this is a SAVE_LAYER, zero out the
         * bit and the next time around, when this is no longer SAVE_LAYER,
         * we will zero out the UNSURE_ENCAP flag.
         */
        if (codec_data.codec_flags & CODEC_SAVE_LAYER)
        {
            codec_data.codec_flags &= ~CODEC_SAVE_LAYER;
            unsure_encap_ptrs = p->ptrs;
        }
        else if (codec_data.codec_flags & CODEC_UNSURE_ENCAP)
            codec_data.codec_flags &= ~CODEC_UNSURE_ENCAP;

        // internal statistics and record keeping
        s_stats[mapped_prot + stat_offset]++; // add correct decode for previous layer
        mapped_prot = CodecManager::s_proto_map[to_utype(codec_data.next_prot_id)];
        prev_prot_id = codec_data.next_prot_id;

        // Shrink the buffer of undecoded data
        const uint16_t curr_lyr_len = codec_data.lyr_len + codec_data.invalid_bytes;
        assert(curr_lyr_len <= raw.len);
        raw.len -= curr_lyr_len;
        raw.data += curr_lyr_len;

        p->proto_bits |= codec_data.proto_bits;

        // Reset the volatile part of the codec data for the next codec to decode into
        codec_data.next_prot_id = ProtocolId::FINISHED_DECODE;
        codec_data.lyr_len = 0;
        codec_data.invalid_bytes = 0;
        codec_data.proto_bits = 0;
    }

    debug_logf(decode_trace, nullptr, "Payload starts at %u, length is %u\n", pktlen - raw.len, raw.len);

    if (p->num_layers > 0)
        s_stats[mapped_prot + stat_offset]++;

    // if the final protocol ID is not the default codec, a Codec failed
    if (prev_prot_id != ProtocolId::FINISHED_DECODE || p->num_layers == 0 )
        handle_decode_failure(p, raw, codec_data, unsure_encap_ptrs, prev_prot_id);

    if (payload_offset_from_daq_mismatch(pkt, raw))
        p->active->set_tunnel_bypass();

    // set any final Packet fields
    p->data = raw.data;
    p->dsize = (uint16_t)raw.len;
    p->proto_bits |= codec_data.proto_bits;

    if (!p->proto_bits)
        p->proto_bits = PROTO_BIT__OTHER;
}

//-------------------------------------------------------------------------
// encoders operate layer by layer:
//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
// encoders:
// - raw pkt data only, no need for Packet stuff except to facilitate
//   encoding
// - don't include original options
// - inner layer differs from original (eg tcp data segment becomes rst)
// - must ensure proper ttl/hop limit for reverse direction
//
// iterate over decoded layers and encode the response packet.  actually
// make nested calls.  on the way in we setup invariant stuff and as we
// unwind the stack we finish up encoding in a more normal fashion (now
// the outer layer knows the length of the inner layer, etc.).
//
// when multiple responses are sent, both forwards and backwards directions,
// or multiple ICMP types (unreachable port, host, net), it may be possible
// to reuse the 1st encoding and just tweak it.  optimization for later
// consideration.

// pci is copied from in to out
// * addresses / ports are swapped if !fwd
// * options, etc. are stripped
// * checksums etc. are set
// * if next layer is udp, it is set to icmp unreachable w/udp
// * if next layer is tcp, it becomes a tcp rst or tcp fin w/opt data
//-------------------------------------------------------------------------

static inline uint8_t GetTTL(const Packet* const p, bool forward)
{
    char dir;
    uint8_t ttl;
    const bool outer = p->ptrs.ip_api.is_ip();

    if ( !p->flow )
        return 0;

    if ( p->is_from_client() )
        dir = forward ? FROM_CLIENT : FROM_SERVER;
    else
        dir = forward ? FROM_SERVER : FROM_CLIENT;

    // outermost ip is considered to be outer here,
    // even if it is the only ip layer ...
    ttl = Stream::get_flow_ttl(p->flow, dir, outer);

    // if we don't get outer, we use inner
    if ( 0 == ttl && outer )
        ttl = Stream::get_flow_ttl(p->flow, dir, false);

    return ttl;
}

bool PacketManager::encode(const Packet* p,
    EncodeFlags flags,
    uint8_t lyr_start,
    IpProtocol next_prot,
    Buffer& buf)
{
    if ( Packet* pe = DetectionEngine::get_encode_packet() )
        p = pe;

    uint8_t ttl = GetTTL(p, (flags & ENC_FLAG_FWD));
    if ( ttl )
        flags |=  ENC_FLAG_TTL;
    else
        ttl = 0;

    if ( SFDAQ::forwarding_packet(p->pkth) )
        flags |= ENC_FLAG_INLINE;

    ip::IpApi tmp_api;
    EncState enc(tmp_api, flags, next_prot, ttl, p->dsize);

    const Layer* const lyrs = p->layers;
    int8_t outer_layer = lyr_start;
    int8_t inner_layer = lyr_start;

    // We need the IP layer associated with every protocol
    // so checksums can be computed.
    while (layer::set_inner_ip_api(p, tmp_api, inner_layer))
    {
        for (int i = outer_layer; i > inner_layer; --i)
        {
            const Layer& l = lyrs[i];
            Codec* cd = get_layer_codec(l, i);
            if (!cd->encode(l.start, l.length, enc, buf, p->flow))
                return false;
        }
        outer_layer = inner_layer;
        // inner_layer is set in 'layer::set_inner_ip_api'
    }

    // Now, we can encode all of the layers between the DLT and
    // outermost IP layer
    tmp_api.reset();
    for (int i = outer_layer; i >= 0; --i)
    {
        const Layer& l = lyrs[i];
        Codec* cd = get_layer_codec(l, i);
        if (!cd->encode(l.start, l.length, enc, buf, p->flow))
            return false;
    }

    return true;
}

const uint8_t* PacketManager::encode_response(
    TcpResponse type, EncodeFlags flags, const Packet* p, uint32_t& len,
    const uint8_t* const payload, uint32_t payload_len)
{
    Buffer buf(s_pkt->data(), s_pkt->size());

    switch (type)
    {
    case TcpResponse::FIN:
        if (payload && (payload_len > 0))
        {
            if (!buf.allocate(payload_len))
                return nullptr;

            memcpy(buf.data(), payload, payload_len);
            flags |= ENC_FLAG_PAY;
        }
        flags |= ENC_FLAG_FIN;
        break;

    case TcpResponse::PUSH:
        if (payload && (payload_len > 0))
        {
            if (!buf.allocate(payload_len))
                return nullptr;

            memcpy(buf.data(), payload, payload_len);
            flags |= ENC_FLAG_PAY;
        }
        flags |= ENC_FLAG_PSH;
        break;

    case TcpResponse::RST:      // No payload, so do nothing.
    default:     // future proof
        break;
    }

    // FIXIT-M check flags if we should skip something
    if (encode(p, flags, p->num_layers-1, IpProtocol::PROTO_NOT_SET, buf))
    {
        len = buf.size();
        return buf.data() + buf.off;
    }

    len = 0;
    return nullptr;
}

const uint8_t* PacketManager::encode_reject(UnreachResponse type,
    EncodeFlags flags, const Packet* p, uint32_t& len)
{
    Buffer buf(s_pkt->data(), s_pkt->size());

    if (p->is_ip4())
    {
        // FIXIT-M check flags if we should skip something
        const int inner_ip_index = layer::get_inner_ip_lyr_index(p);
        assert(inner_ip_index >= 0);
        assert(inner_ip_index+1 < p->num_layers);

        /*  Building this packet from the inside out */
        if (!buf.allocate(icmp::ICMP_UNREACH_DATA_LEN))
            return nullptr;

        memcpy(buf.data(), p->layers[inner_ip_index+1].start, icmp::ICMP_UNREACH_DATA_LEN);

        const ip::IP4Hdr* const ip4h =
            reinterpret_cast<const ip::IP4Hdr*>(p->layers[inner_ip_index].start);
        const uint8_t ip_len = ip4h->hlen();

        if (!buf.allocate(ip_len))
            return nullptr;
        memcpy(buf.data(), ip4h, ip_len);

        // If this returns false, we're down pig creek.
        if (!buf.allocate(sizeof(icmp::Icmp4Base)))
            return nullptr;

        icmp::Icmp4Base* const icmph = reinterpret_cast<icmp::Icmp4Base*>(buf.data());
        icmph->type = icmp::IcmpType::DEST_UNREACH;
        icmph->csum = 0;
        icmph->opt32 = 0;

        switch (type)
        {
        case UnreachResponse::NET:
            icmph->code = icmp::IcmpCode::NET_UNREACH;
            break;
        case UnreachResponse::HOST:
            icmph->code = icmp::IcmpCode::HOST_UNREACH;
            break;
        case UnreachResponse::PORT:
            icmph->code = icmp::IcmpCode::PORT_UNREACH;
            break;
        case UnreachResponse::FWD:
            icmph->code = icmp::IcmpCode::PKT_FILTERED;
            break;
        default:     // future proofing
            icmph->code = icmp::IcmpCode::PORT_UNREACH;
        }

        icmph->csum = checksum::icmp_cksum((uint16_t*)buf.data(), buf.size());

        if (encode(p, flags, inner_ip_index, IpProtocol::ICMPV4, buf))
        {
            len = buf.size();
            return buf.data() + buf.off;
        }

        len = 0;
        return nullptr;
    }
    else if (p->is_ip6())
    {
        // FIXIT-M check flags if we should skip ip6_options
        const int inner_ip_index = layer::get_inner_ip_lyr_index(p);
        assert(inner_ip_index >= 0);
        assert(inner_ip_index+1 < p->num_layers);

        // FIXIT-L copy up to minimum MTU worth of data
        // FIXIT-L check if we have the full 8 bytes of data.
        if (!buf.allocate(icmp::ICMP_UNREACH_DATA_LEN))
            return nullptr;
        memcpy(buf.data(), p->layers[inner_ip_index+1].start, icmp::ICMP_UNREACH_DATA_LEN);

        // copy original ip header
        if (!buf.allocate(ip::IP6_HEADER_LEN))
            return nullptr;
        const ip::IP6Hdr* const ip6h = p->ptrs.ip_api.get_ip6h();
        memcpy(buf.data(), ip6h, ip::IP6_HEADER_LEN);

        if (!buf.allocate(sizeof(icmp::Icmp6Hdr)))
            return nullptr;

        icmp::Icmp6Hdr* const icmph = reinterpret_cast<icmp::Icmp6Hdr*>(buf.data());
        icmph->type = icmp::Icmp6Types::DESTINATION_UNREACHABLE;
        icmph->csum = 0;
        icmph->opt32 = 0;

        switch (type)
        {
        case UnreachResponse::NET:
            icmph->code = icmp::Icmp6Code::UNREACH_NET;
            break;
        case UnreachResponse::HOST:
            icmph->code = icmp::Icmp6Code::UNREACH_HOST;
            break;
        case UnreachResponse::PORT:
            icmph->code = icmp::Icmp6Code::UNREACH_PORT;
            break;
        case UnreachResponse::FWD:
            icmph->code = icmp::Icmp6Code::UNREACH_FILTER_PROHIB;
            break;
        default:     // future proofing
            icmph->code = icmp::Icmp6Code::UNREACH_PORT;
        }

        checksum::Pseudoheader6 ps6;
        const int ip_len = buf.size();
        memcpy(ps6.hdr.sip, ip6h->get_src()->u6_addr8, sizeof(ps6.hdr.sip));
        memcpy(ps6.hdr.dip, ip6h->get_dst()->u6_addr8, sizeof(ps6.hdr.dip));
        ps6.hdr.zero = 0;
        ps6.hdr.protocol = IpProtocol::ICMPV6;
        ps6.hdr.len = htons((uint16_t)(ip_len));

        icmph->csum = checksum::icmp_cksum((uint16_t*)buf.data(), ip_len, ps6);

        if (encode(p, flags, inner_ip_index, IpProtocol::ICMPV6, buf))
        {
            len = buf.size();
            return buf.data() + buf.off;
        }

        len = 0;
        return nullptr;
    }
    else
    {
        return nullptr;
    }
}

static void init_daq_pkthdr(
    const Packet* p, Packet* c, const DAQ_PktHdr_t* phdr, uint32_t opaque)
{
    if ( !phdr )
        phdr = p->pkth;

    assert(c->pkth == c->context->pkth);
    DAQ_PktHdr_t* pkth = c->context->pkth;
    pkth->ingress_index = phdr->ingress_index;
    pkth->ingress_group = phdr->ingress_group;
    pkth->egress_index = phdr->egress_index;
    pkth->egress_group = phdr->egress_group;
    pkth->flags = phdr->flags;
    pkth->address_space_id = phdr->address_space_id;
    pkth->tenant_id = phdr->tenant_id;
    pkth->opaque = opaque;
}

//-------------------------------------------------------------------------
// formatters:
// - these packets undergo detection
// - need to set Packet stuff except for frag which calls grinder
// - include original options except for frag inner ip
// - inner layer header is very similar but payload differs
// - original ttl is always used
//-------------------------------------------------------------------------

int PacketManager::format_tcp(
    EncodeFlags, const Packet* p, Packet* c, PseudoPacketType type,
    const DAQ_PktHdr_t* phdr, uint32_t opaque)
{
    uint32_t cflags = c->packet_flags;
    c->reset();
    init_daq_pkthdr(p, c, phdr, opaque);

    c->packet_flags = cflags | PKT_PSEUDO;
    c->pseudo_type = type;

    // cooked packet gets same policy as raw
    c->user_inspection_policy_id = p->user_inspection_policy_id;
    c->user_ips_policy_id = p->user_ips_policy_id;
    c->user_network_policy_id = p->user_network_policy_id;
    c->ip_proto_next = p->ip_proto_next;

    // setup pkt capture header
    c->pktlen = 0;
    assert(c->pkth == c->context->pkth);
    c->context->pkth->pktlen = 0;
    c->context->pkth->ts = p->pkth->ts;

    return 0;
}

int PacketManager::encode_format(
    EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type,
    const DAQ_PktHdr_t* phdr, uint32_t opaque)
{
    bool update_ip4_len = false;
    uint8_t num_layers;

    if ( f & ENC_FLAG_DEF )
    {
        /*
         * By its definitions, this flag means 'stop before innermost ip4
         * opts or ip6 frag header'. So, stop after the ip4 layer IP4 will format itself, and now
         * we ensure that the ip6_frag header is not copied too.
         */

        if ( p->is_ip6() )
        {
            num_layers = layer::get_inner_ip6_frag_index(p);
        }
        else
        {
            num_layers = layer::get_inner_ip_lyr_index(p) + 1;
            update_ip4_len = true;
        }
    }
    else if ( f & ENC_FLAG_NET )
        num_layers = layer::get_inner_ip_lyr_index(p) + 1;
    else
        num_layers = p->num_layers;

    if ( num_layers == 0 )
        return -1;

    init_daq_pkthdr(p, c, phdr, opaque);

    // copy raw packet data to clone
    Layer* lyr = &p->layers[num_layers - 1];
    int len = lyr->start - p->pkt + lyr->length;
    memcpy((void*)c->pkt, p->pkt, len);

    const bool reverse = !(f & ENC_FLAG_FWD);

    // set up and format layers
    for ( int i = 0; i < num_layers; i++ )
    {
        const uint8_t* b = c->pkt + (p->layers[i].start - p->pkt); // == c->pkt + p->layers[i].len
        lyr = &c->layers[i];

        lyr->prot_id = p->layers[i].prot_id;
        lyr->length = p->layers[i].length;
        lyr->start = b;

        // NOTE: this must always go from outer to inner
        //       to ensure a valid ip header
        Codec* cd = get_layer_codec(*lyr, i);
        cd->format(reverse, const_cast<uint8_t*>(lyr->start), c->ptrs);
    }

    if ( update_ip4_len )
    {
        lyr = &c->layers[num_layers - 1];
        ip::IP4Hdr* ip4h = reinterpret_cast<ip::IP4Hdr*>(const_cast<uint8_t*>(lyr->start));
        lyr->length = ip::IP4_HEADER_LEN;
        ip4h->set_ip_len(ip::IP4_HEADER_LEN);
        ip4h->set_hlen(ip::IP4_HEADER_LEN >> 2);
    }

    // setup payload info
    c->num_layers = num_layers;
    c->data = lyr->start + lyr->length;
    len = c->data - c->pkt;

    // len < ETHERNET_HEADER_LEN + VLAN_HEADER + ETHERNET_MTU
    assert((unsigned)len < Codec::PKT_MAX - c->max_dsize);

    c->proto_bits = p->proto_bits;
    c->ip_proto_next = p->ip_proto_next;
    c->packet_flags |= PKT_PSEUDO;
    c->pseudo_type = type;

    // cooked packet gets same policy as raw
    c->user_inspection_policy_id = p->user_inspection_policy_id;
    c->user_ips_policy_id = p->user_ips_policy_id;
    c->user_network_policy_id = p->user_network_policy_id;

    // setup pkt capture header
    c->pktlen = len;
    assert(c->pkth == c->context->pkth);
    c->context->pkth->pktlen = len;
    c->context->pkth->ts = p->pkth->ts;

    layer::set_packet_pointer(c);  // ensure we are looking at the new packet
    return 0;
}

//-------------------------------------------------------------------------
// updaters:  these functions set length and checksum fields, only needed
// when a packet is modified.  some packets only have replacements so only
// the checksums need to be updated.  we always set the length rather than
// checking each time if needed.
//-------------------------------------------------------------------------

static inline void add_flag(
    UpdateFlags& flags, UpdateFlags flag_to_add, const Packet* const p,
    decltype(Packet::packet_flags)pkt_flag)  // future proofing.
{
    if ( p->packet_flags & pkt_flag )
        flags |= flag_to_add;
}

void PacketManager::encode_update(Packet* p)
{
    uint32_t len = p->dsize;

    UpdateFlags flags = 0;
    add_flag(flags, UPD_COOKED, p, PKT_PSEUDO);
    add_flag(flags, UPD_MODIFIED, p, PKT_MODIFIED);
    add_flag(flags, UPD_RESIZED, p, PKT_RESIZED);
    add_flag(flags, UPD_REBUILT_FRAG, p, PKT_REBUILT_FRAG);

    int8_t outer_layer = p->num_layers-1;
    int8_t inner_layer = p->num_layers-1;
    const Layer* const lyr = p->layers;
    ip::IpApi tmp_api;

    // update the rest of the ip layers with the correct IP reference.
    while (layer::set_inner_ip_api(p, tmp_api, inner_layer))
    {
        for (int i = outer_layer; i > inner_layer; --i)
        {
            const Layer& l = lyr[i];
            Codec* cd = get_layer_codec(l, i);
            cd->update(tmp_api, flags, const_cast<uint8_t*>(l.start), l.length, len);
        }
        outer_layer = inner_layer;
        // inner_layer is set in 'layer::set_inner_ip_api'
    }

    tmp_api.reset();
    for (int i = outer_layer; i >= 0; --i)
    {
        const Layer& l = lyr[i];
        ProtocolIndex mapped_prot = CodecManager::s_proto_map[to_utype(l.prot_id)];
        CodecManager::s_protocols[mapped_prot]->update(
            tmp_api, flags, const_cast<uint8_t*>(l.start), l.length, len);
    }

    if ( !(p->packet_flags & PKT_MODIFIED) || (p->packet_flags & PKT_RESIZED) )
    {
        p->pktlen = len;
        // Only attempt to update the DAQ packet header for manufactured (defragged) packets.  If
        // this is the original wire packet, leave the header alone; the drop/inject for resize
        // will use pktlen from Packet for the injection length.
        // FIXIT-L there should be a better way to detect that this is manufactured packet
        if (p->pkth == p->context->pkth)
            p->context->pkth->pktlen = len;
    }
}

//-------------------------------------------------------------------------
// codec support and statistics
//-------------------------------------------------------------------------

uint16_t PacketManager::encode_get_max_payload(const Packet* p)
{
    if ( !p->num_layers )
        return 0;

    const Layer& l = p->layers[p->num_layers - 1];
    return ETHERNET_MTU - (l.start - p->layers[0].start) - l.length;
}

void PacketManager::dump_stats()
{
    std::vector<const char*> pkt_names;

    // zero out the default codecs
    g_stats[stat_offset] = 0;
    g_stats[CodecManager::s_proto_map[to_utype(ProtocolId::FINISHED_DECODE)] + stat_offset] = 0;

    for (unsigned int i = 0; i < stat_names.size(); i++)
        pkt_names.emplace_back(stat_names[i]);

    for (int i = 0; CodecManager::s_protocols[i] != nullptr; i++)
        pkt_names.emplace_back(CodecManager::s_protocols[i]->get_name());

    show_percent_stats((PegCount*)&g_stats, &pkt_names[0],
        (unsigned int)pkt_names.size(), "codec");
}

void PacketManager::reset_stats()
{
    std::fill(std::begin(g_stats), std::end(g_stats), 0);
    std::fill(std::begin(s_stats), std::end(s_stats), 0);
}

void PacketManager::accumulate()
{
    static std::mutex stats_mutex;

    std::lock_guard<std::mutex> lock(stats_mutex);
    sum_stats(&g_stats[0], &s_stats[0], s_stats.size());

    // mutex is automatically unlocked
}

const char* PacketManager::get_proto_name(ProtocolId protocol)
{ return CodecManager::s_protocols[CodecManager::s_proto_map[to_utype(protocol)]]->get_name(); }

const char* PacketManager::get_proto_name(IpProtocol protocol)
{ return CodecManager::s_protocols[CodecManager::s_proto_map[to_utype(protocol)]]->get_name(); }

void PacketManager::log_protocols(TextLog* const text_log,
    const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* const lyr = p->layers;

    if (num_layers != 0)
    {
        int i = 0;
        // Special case for root codecs not registering a protocol ID
        if (lyr[0].prot_id == CodecManager::grinder_id || lyr[0].prot_id == ProtocolId::FINISHED_DECODE)
        {
            Codec* cd = CodecManager::s_protocols[CodecManager::grinder];
            TextLog_Print(text_log, "%s(DLT):  ", cd->get_name());
            cd->log(text_log, lyr[0].start, lyr[0].length);
            i++;
        }

        for (; i < num_layers; i++)
        {
            const auto protocol = to_utype(lyr[i].prot_id);
            const uint8_t codec_offset =  CodecManager::s_proto_map[protocol];
            Codec* cd = CodecManager::s_protocols[codec_offset];

            TextLog_NewLine(text_log);
            TextLog_Print(text_log, "%s", cd->get_name());

            if (protocol <= 0xFF)
                TextLog_Print(text_log, "(0x%02x)", protocol);
            else
                TextLog_Print(text_log, "(0x%04x)", protocol);

            TextLog_Puts(text_log, ":  ");
            cd->log(text_log, lyr[i].start, lyr[i].length);
        }
    }
}
