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
// packet_manager.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <vector>
#include <cstring>
#include <mutex>
#include <algorithm>

#include "framework/codec.h"
#include "managers/codec_manager.h"
#include "managers/packet_manager.h"
#include "main/snort.h"
#include "main/thread.h"
#include "log/messages.h"

#include "protocols/packet.h"
#include "protocols/protocol_ids.h"
#include "time/profiler.h"
#include "parser/parser.h"

#include "codecs/ip/ip_util.h"
#include "codecs/codec_events.h"
#include "codecs/decode_module.h"
#include "utils/stats.h"


#ifdef PERF_PROFILING
THREAD_LOCAL ProfileStats decodePerfStats;
#endif

// Decoding statistics

// this may be my longer member declaration ... ever
THREAD_LOCAL std::array<PegCount,PacketManager::stat_offset +
    CodecManager::s_protocols.size()> PacketManager::s_stats{{0}};

//PacketManager::s_stats{{0}};
std::array<PegCount, PacketManager::s_stats.size()> PacketManager::g_stats;

// names which will be printed for the first three statistics
// in s_stats/g_stats
const std::array<const char*, PacketManager::stat_offset> PacketManager::stat_names =
{
    {
        "total",
        "other",
        "discards"
    }
};


// Encoder Foo
static THREAD_LOCAL Packet *encode_pkt;
static THREAD_LOCAL PegCount total_rebuilt_pkts = 0;
static THREAD_LOCAL std::array<uint8_t, Codec::PKT_MAX> s_pkt{{0}};

// FIXIT-L this shouldn't have to be thread lcoal
static THREAD_LOCAL uint8_t* dst_mac = NULL;

//-------------------------------------------------------------------------
// Private helper functions
//-------------------------------------------------------------------------

static inline void push_layer(Packet *p,
                                uint16_t prot_id,
                                const uint8_t *hdr_start,
                                uint32_t len,
                                Codec *const cd)
{
    if ( p->num_layers < LAYER_MAX )
    {
        Layer& lyr = p->layers[p->num_layers++];
        lyr.proto = cd->get_proto_id();
        lyr.prot_id = prot_id;
        lyr.start = (uint8_t*)hdr_start;
        lyr.length = (uint16_t)len;
    }
    else
    {
        LogMessage("(packet_manager) WARNING: decoder has too many layers;"
            " next proto is something.\n");
    }
}

//-------------------------------------------------------------------------
// Initialization and setup
//-------------------------------------------------------------------------

Packet* PacketManager::encode_new ()
{
    Packet* p = (Packet*)SnortAlloc(sizeof(*p));
    uint8_t* b = (uint8_t*)SnortAlloc(sizeof(*p->pkth) + Codec::PKT_MAX + SPARC_TWIDDLE);

    if ( !p || !b )
        FatalError("encode_new() => Failed to allocate packet\n");

    p->pkth = (DAQ_PktHdr_t*)b;
    b += sizeof(*p->pkth);
    b += SPARC_TWIDDLE;
    p->pkt = b;

    return p;
}

void PacketManager::encode_delete (Packet* p)
{
    free((void*)p->pkth);  // cast away const!
    free(p);
}


//-------------------------------------------------------------------------
// Encode/Decode functions
//-------------------------------------------------------------------------

void PacketManager::decode(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    PROFILE_VARS;
    uint16_t prot_id;
    uint8_t mapped_prot = CodecManager::grinder;
    uint16_t prev_prot_id = FINISHED_DECODE;
    uint16_t lyr_len = 0;
    uint32_t len;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)pkthdr->caplen, (unsigned long)pkthdr->pktlen);
            );

    MODULE_PROFILE_START(decodePerfStats);

    // initialize all of the relevent data to decode this packet
    memset(p, 0, PKT_ZERO_LEN);
    p->ip_api.reset();

    p->pkth = pkthdr;
    p->pkt = pkt;
    len = pkthdr->caplen;

    s_stats[total_processed]++;

    // loop until the protocol id is no longer valid
    while(CodecManager::s_protocols[mapped_prot]->decode(pkt, len, p, lyr_len, prot_id))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Codec %s (protocol_id: %u:"
                "ip header starts at: %p, length is %lu\n",
                CodecManager::s_protocols[mapped_prot]->get_name(), prot_id, pkt,
                (unsigned long) len););

        // must be done here after decode and before push for case layer
        // LAYER_MAX+1 is invalid or the default codec
        if ( p->num_layers == LAYER_MAX )
        {
            codec_events::decoder_event(p, DECODE_TOO_MANY_LAYERS);
            p->dsize = (uint16_t)len;
            p->data = pkt;
            MODULE_PROFILE_END(decodePerfStats);
            return /*false */;
        }

        // internal statistics and record keeping
        push_layer(p, prev_prot_id, pkt, lyr_len, CodecManager::s_protocols[mapped_prot]);
        s_stats[mapped_prot + stat_offset]++;
        mapped_prot = CodecManager::s_proto_map[prot_id];
        prev_prot_id = prot_id;

        // set for next call
        prot_id = FINISHED_DECODE;
        len -= lyr_len;
        pkt += lyr_len;
        lyr_len = 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Codec %s (protocol_id: %hu: ip header"
                    " starts at: %p, length is %lu\n",
                     CodecManager::s_protocols[mapped_prot]->get_name(),
                     prot_id, pkt, (unsigned long) len););


    // if the final protocol ID is not the default codec, a Codec failed
    if (prev_prot_id != FINISHED_DECODE)
    {
        if (!(p->decode_flags & DECODE__UNSURE_ENCAP))
        {
            // if the codec exists, it failed
            if(CodecManager::s_proto_map[prev_prot_id])
                s_stats[discards]++;
            else
                s_stats[other_codecs]++;
        }
        else
        {
            // nested 'if' for when we have addtional code in UNSURE_ENCAP

            // Hardcodec ESP because we trust if an only if the layer
            // immediately following ESP fails.
            if (p->layers[p->num_layers].prot_id == IPPROTO_ID_ESP)
                p->packet_flags |= PKT_TRUST;
        }
    }


    if (ScMaxEncapsulations() != -1 &&
        p->encapsulations > ScMaxEncapsulations())
    {
        codec_events::decoder_event(p, DECODE_IP_MULTIPLE_ENCAPSULATION);
    }

    if (p->ip6_extension_count > 0)
        ip_util::CheckIPv6ExtensionOrder(p);

    s_stats[mapped_prot + stat_offset]++;

    /*
     * NOTE:  NEVER RETURN BEFORE SETTING THESE TWO VARIABLES!!
     *        they are no longer zeroed above, which means if they
     *        unset, undefined behavior will ensure
     */
    p->dsize = (uint16_t)len;
    p->data = pkt;

    MODULE_PROFILE_END(decodePerfStats);
}

bool PacketManager::has_codec(uint16_t cd_id)
{ return CodecManager::s_protocols[cd_id] != 0; }


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
// - sparc twiddle must be factored in packet start for transmission
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

const uint8_t* PacketManager::encode_response(
    EncodeType type, EncodeFlags flags, const Packet* p, uint32_t* len,
    const uint8_t* payLoad, uint32_t payLen)
{
    EncState enc;

    enc.type = type;
    enc.flags = flags;

    enc.payLoad = payLoad;
    enc.payLen = payLen;
    enc.proto = 0;

    if ( encode_pkt )
        p = encode_pkt;


    Buffer obuf;
    obuf.base = s_pkt.data() + s_pkt.size() + 1;
    obuf.off = obuf.end = 0;
    obuf.size = sizeof(s_pkt);

    // setting convenience pointers
    enc.layer = p->num_layers;
    enc.p = p;

    const Layer *lyrs = p->layers;
    for(int i = p->num_layers-1; i >= 0; i--)
    {
        // lots of room for improvement
        const Layer *l = &lyrs[i];
        enc.layer--;

        // layer 0 is the data link type and doesn't have a protocol id.
        uint8_t mapped_prot = i ? CodecManager::s_proto_map[l->prot_id] : CodecManager::grinder;
        if (!CodecManager::s_protocols[mapped_prot]->encode(&enc, &obuf, l->start))
        {
            *len = 0;
            return nullptr;
        }
    }


    *len = (uint32_t)obuf.end;
    return obuf.base + obuf.off;
}

//-------------------------------------------------------------------------
// formatters:
// - these packets undergo detection
// - need to set Packet stuff except for frag3 which calls grinder
// - include original options except for frag3 inner ip
// - inner layer header is very similar but payload differs
// - original ttl is always used
//-------------------------------------------------------------------------
int PacketManager::encode_format_with_daq_info (
    EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type,
    const DAQ_PktHdr_t* phdr, uint32_t opaque)
{
    int i;
    Layer* lyr;
    int len;
    int num_layers = p->num_layers;
    DAQ_PktHdr_t* pkth = (DAQ_PktHdr_t*)c->pkth;

    if ( num_layers <= 0 )
        return -1;

    memset(c, 0, PKT_ZERO_LEN);


#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    pkth->ingress_index = phdr->ingress_index;
    pkth->ingress_group = phdr->ingress_group;
    pkth->egress_index = phdr->egress_index;
    pkth->egress_group = phdr->egress_group;
    pkth->flags = phdr->flags & (~DAQ_PKT_FLAG_HW_TCP_CS_GOOD);
    pkth->address_space_id = phdr->address_space_id;
    pkth->opaque = opaque;
#elif defined(HAVE_DAQ_ACQUIRE_WITH_META)
    pkth->opaque = opaque;
    UNUSED(phdr);
#else
    UNUSED(phdr);
    UNUSED(opaque);
#endif

    if ( f & ENC_FLAG_NET )
    {
        num_layers = layer::get_inner_ip_lyr(p) + 1;

        // TBD:  is this an extraneous check?
        if (num_layers == 0)
            return -1;
    }

    // copy raw packet data to clone
    lyr = (Layer*)p->layers + num_layers - 1;
    len = lyr->start - p->pkt + lyr->length;
    memcpy((void*)c->pkt, p->pkt, len);

    // set up and format layers
    for ( i = 0; i < num_layers; i++ )
    {
        const uint8_t* b = c->pkt + (p->layers[i].start - p->pkt); // == c->pkt + p->layers[i].len
        lyr = c->layers + i;

        lyr->proto = p->layers[i].proto;
        lyr->prot_id = p->layers[i].prot_id;
        lyr->length = p->layers[i].length;
        lyr->start = (uint8_t*)b;

        // NOTE: this must always go from outer to inner
        //       to ensure a valid ip header
        uint8_t mapped_prot = i ? CodecManager::s_proto_map[lyr->prot_id] : CodecManager::grinder;
        CodecManager::s_protocols[mapped_prot]->format(f, p, c, lyr);
    }

    // setup payload info
    c->num_layers = num_layers;
    c->data = lyr->start + lyr->length;
    len = c->data - c->pkt;

    // len < ETHERNET_HEADER_LEN + VLAN_HEADER + ETHERNET_MTU
    assert((unsigned)len < Codec::PKT_MAX - IP_MAXPACKET);

    c->max_dsize = IP_MAXPACKET - len;
    c->proto_bits = p->proto_bits;
    c->packet_flags |= PKT_PSEUDO;
    c->pseudo_type = type;
    c->user_policy_id = p->user_policy_id;  // cooked packet gets same policy as raw

    // setup pkt capture header
    pkth->caplen = len;
    pkth->pktlen = len;
    pkth->ts = p->pkth->ts;

    total_rebuilt_pkts++;  // update local counter
    return 0;
}


#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
int PacketManager::encode_format(EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type)
{
    return encode_format_with_daq_info(f, p, c, type, p->pkth, p->pkth->opaque);
}
#elif defined(HAVE_DAQ_ACQUIRE_WITH_META)
int PacketManager::encode_format(EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type)
{
    return encode_format_with_daq_info(f, p, c, type, nullptr, p->pkth->opaque);
}
#else
int PacketManager::encode_format(EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type)
{
    return encode_format_with_daq_info(f, p, c, type, nullptr, 0);
}
#endif

//-------------------------------------------------------------------------
// updaters:  these functions set length and checksum fields, only needed
// when a packet is modified.  some packets only have replacements so only
// the checksums need to be updated.  we always set the length rather than
// checking each time if needed.
//-------------------------------------------------------------------------

void PacketManager::encode_update (Packet* p)
{
    int i;
    uint32_t len = 0;
    DAQ_PktHdr_t* pkth = (DAQ_PktHdr_t*)p->pkth;

    Layer *lyr = p->layers;

    for ( i = p->num_layers - 1; i >= 0; i-- )
    {
        Layer *l = lyr + i;

        uint8_t mapped_prot = i ? CodecManager::s_proto_map[l->prot_id] : CodecManager::grinder;
        CodecManager::s_protocols[mapped_prot]->update(p, l, &len);
    }
    // see IP6_Update() for an explanation of this ...
    if ( !(p->packet_flags & PKT_MODIFIED)
        || (p->packet_flags & PKT_RESIZED)
    )
        pkth->caplen = pkth->pktlen = len;
}

//-------------------------------------------------------------------------
// codec support and statistics
//-------------------------------------------------------------------------


void PacketManager::encode_set_dst_mac(uint8_t *mac)
{ dst_mac = mac; }

uint8_t *PacketManager::encode_get_dst_mac()
{ return dst_mac; }

uint64_t PacketManager::get_rebuilt_packet_count(void)
{ return total_rebuilt_pkts; }

void PacketManager::encode_set_pkt(Packet* p)
{ encode_pkt = p; }


void PacketManager::dump_stats()
{
    std::vector<const char*> pkt_names;

    // zero out the default codecs
    g_stats[3] = 0;
    g_stats[CodecManager::s_proto_map[FINISHED_DECODE] + stat_offset] = 0;

    for(unsigned int i = 0; i < stat_names.size(); i++)
        pkt_names.push_back(stat_names[i]);

    for(int i = 0; CodecManager::s_protocols[i] != 0; i++)
        pkt_names.push_back(CodecManager::s_protocols[i]->get_name());

    show_percent_stats((PegCount*) &g_stats, &pkt_names[0], (unsigned int) pkt_names.size(),
        "codec");
}

void PacketManager::accumulate()
{
    static std::mutex stats_mutex;

    stats_mutex.lock();
    sum_stats(&g_stats[0], &s_stats[0], s_stats.size());
    stats_mutex.unlock();
}

