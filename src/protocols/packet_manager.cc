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
#include <type_traits> // static_assert

#include "framework/codec.h"
#include "managers/codec_manager.h"
#include "protocols/packet_manager.h"
#include "main/snort.h"
#include "main/thread.h"
#include "log/messages.h"

#include "protocols/packet.h"
#include "protocols/protocol_ids.h"
#include "protocols/eth.h"
#include "time/profiler.h"
#include "parser/parser.h"

#include "codecs/codec_events.h"
#include "codecs/decode_module.h"
#include "utils/stats.h"
#include "log/text_log.h"
#include "main/snort_debug.h"
#include "detection/fpdetect.h"


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
static THREAD_LOCAL Packet *encode_pkt = nullptr;
static THREAD_LOCAL PegCount total_rebuilt_pkts = 0;
static THREAD_LOCAL std::array<uint8_t, Codec::PKT_MAX> s_pkt{{0}};
static THREAD_LOCAL uint8_t* dst_mac = nullptr;
static THREAD_LOCAL SnortData tmp_ptrs;

//-------------------------------------------------------------------------
// Private helper functions
//-------------------------------------------------------------------------

static inline void push_layer(Packet *p,
                                uint16_t prot_id,
                                const uint8_t *hdr_start,
                                uint32_t len,
                                Codec *const cd)
{

    // We check to ensure num_layer < MAX_LAYERS before this function call
    Layer& lyr = p->layers[p->num_layers++];
    lyr.proto = cd->get_proto_id();
    lyr.prot_id = prot_id;
    lyr.start = hdr_start;
    lyr.length = (uint16_t)len;
//    lyr.invalid_bits = p->byte_skip;  -- currently unused
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
    if (p)
    {
        if (p->pkth)
            free((void*)p->pkth);  // cast away const!

        free(p);
    }
}

// Assertions required for this code to work

//  Look below inside main decode() loop for these static_asserts
static_assert(CODEC_ENCAP_LAYER == (CODEC_UNSURE_ENCAP | CODEC_SAVE_LAYER),
    "If this is an encapsulated layer, you must also set UNSURE_ENCAP"
    " and SAVE_LAYER");


//-------------------------------------------------------------------------
// Encode/Decode functions
//-------------------------------------------------------------------------

void PacketManager::decode(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    PROFILE_VARS;
    uint8_t mapped_prot = CodecManager::grinder;
    uint16_t prev_prot_id = FINISHED_DECODE;


//    assert(!(p->packet_flags & PKT_REBUILT_STREAM));


    // initialize all Packet information
    memset(p, 0, PKT_ZERO_LEN);
    p->pkth = pkthdr;
    p->pkt = pkt;
    p->ptrs.reset();
    layer::set_packet_pointer(p);


    RawData raw{pkt, pkthdr->caplen};
    CodecData codec_data(FINISHED_DECODE);

    MODULE_PROFILE_START(decodePerfStats);
    s_stats[total_processed]++;

    // loop until the protocol id is no longer valid
    while(CodecManager::s_protocols[mapped_prot]->decode(raw, codec_data, p->ptrs))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Codec %s (protocol_id: %u:"
                "ip header starts at: %p, length is %lu\n",
                CodecManager::s_protocols[mapped_prot]->get_name(),
                codec_data.next_prot_id, pkt, codec_data.lyr_len););

        // must be done here after decode and before push for case layer
        // LAYER_MAX+1 is invalid or the default codec
        if ( p->num_layers == LAYER_MAX )
        {
            SnortEventqAdd(GID_DECODE, DECODE_TOO_MANY_LAYERS);
            p->data = raw.data;
            p->dsize = (uint16_t)raw.len;
            MODULE_PROFILE_END(decodePerfStats);
            return /*false */;
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
            tmp_ptrs = p->ptrs;
        }
        else
        {
            // faster to just get rid fo bit than test & set
            codec_data.codec_flags &= ~CODEC_UNSURE_ENCAP;
        }

        if (codec_data.proto_bits & (PROTO_BIT__IP | PROTO_BIT__IP6_EXT))
            fpEvalIpProtoOnlyRules(p, codec_data.next_prot_id);


        // internal statistics and record keeping
        push_layer(p, prev_prot_id, raw.data, codec_data.lyr_len, CodecManager::s_protocols[mapped_prot]);
        s_stats[mapped_prot + stat_offset]++; // add correct decode for previous layer
        mapped_prot = CodecManager::s_proto_map[codec_data.next_prot_id];
        prev_prot_id = codec_data.next_prot_id;



        // set for next call
        const uint16_t curr_lyr_len = codec_data.lyr_len + codec_data.invalid_bytes;
        raw.len -= curr_lyr_len;
        raw.data += curr_lyr_len;
        p->proto_bits |= codec_data.proto_bits;
        codec_data.next_prot_id = FINISHED_DECODE;
        codec_data.lyr_len = 0;
        codec_data.invalid_bytes = 0;
        codec_data.proto_bits = 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Codec %s (protocol_id: %hu: ip header"
                    " starts at: %p, length is %lu\n",
                     CodecManager::s_protocols[mapped_prot]->get_name(),
                     prev_prot_id, pkt, (unsigned long) codec_data.lyr_len););

    s_stats[mapped_prot + stat_offset]++;

    // if the final protocol ID is not the default codec, a Codec failed
    if (prev_prot_id != FINISHED_DECODE)
    {
        if (codec_data.codec_flags & CODEC_UNSURE_ENCAP)
        {
            p->ptrs = tmp_ptrs;

            // Hardcodec ESP because we trust iff the layer
            // immediately preceding the fail is ESP.
            if (p->layers[p->num_layers].prot_id == IPPROTO_ID_ESP)
                p->ptrs.decode_flags |= DECODE_PKT_TRUST;
        }
        else
        {
            // if the codec exists, it failed
            if(CodecManager::s_proto_map[prev_prot_id])
                s_stats[discards]++;
            else
                s_stats[other_codecs]++;
        }
    }

    // set any final Packet fields
    p->proto_bits |= codec_data.proto_bits;
    p->data = raw.data;
    p->dsize = (uint16_t)raw.len;
    MODULE_PROFILE_END(decodePerfStats);
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
        num_layers = layer::get_inner_ip_lyr_index(p) + 1;

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


    layer::set_packet_pointer(c);  // set layer pointer to ensure lookin at the new packet
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
    // FIXIT-L J   is this second statement really necessary?
    // PKT_RESIZED include PKT_MODIFIED ... so get rid of that extra flag
    if ( !(p->packet_flags & PKT_MODIFIED)
        || (p->packet_flags & (PKT_RESIZED & ~PKT_MODIFIED))
    )
    {
        pkth->caplen = pkth->pktlen = len;
    }
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

    show_percent_stats((PegCount*) &g_stats, &pkt_names[0],
        (unsigned int) pkt_names.size(), "codec");
}

void PacketManager::accumulate()
{
    static std::mutex stats_mutex;

    std::lock_guard<std::mutex> lock(stats_mutex);
    sum_stats(&g_stats[0], &s_stats[0], s_stats.size());

    // mutex is automatically unlocked
}


const char* PacketManager::get_proto_name(uint16_t protocol)
{ return CodecManager::s_protocols[CodecManager::s_proto_map[protocol]]->get_name(); }

const char* PacketManager::get_proto_name(uint8_t protocol)
{ return CodecManager::s_protocols[CodecManager::s_proto_map[protocol]]->get_name(); }


void PacketManager::log_protocols(TextLog* const text_log,
                                        const Packet* const p)
{
    uint8_t num_layers = p->num_layers;
    const Layer* const lyr = p->layers;
//    int pos = TextLog_Tell(text_log);

    if (num_layers != 0)
    {
        // Grinder is not in the layer array
        Codec* const cd = CodecManager::s_protocols[CodecManager::grinder];

        TextLog_Print(text_log, "%-.6s(DLT):  ", cd->get_name());
        cd->log(text_log, lyr[0].start, p);



        for (int i = 1; i < num_layers; i++)
        {
            const uint16_t protocol = lyr[i].prot_id;
            const uint8_t codec_offset =  CodecManager::s_proto_map[protocol];
            Codec* const cd = CodecManager::s_protocols[codec_offset];


            TextLog_NewLine(text_log);
            TextLog_Print(text_log, "%-.*s", 6, cd->get_name());

            // don't print the type if this is a custom type.  Look
            // in protocol_ids.h for more details.
            if (protocol <= 0xFF)
                TextLog_Print(text_log, "(0x%02x)", protocol);
            else if (protocol >= eth::MIN_ETHERTYPE)
                TextLog_Print(text_log, "(0x%04x)", protocol);

            TextLog_Puts(text_log, ":  ");
            cd->log(text_log, lyr[i].start, p);
        }
    }
}
