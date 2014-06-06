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
// packet_manager.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <vector>
#include <cstring>
#include <mutex>
#include <algorithm>

#include "packet_manager.h"
#include "framework/codec.h"
#include "snort.h"
#include "main/thread.h"
#include "log/messages.h"
#include "packet_io/sfdaq.h"

#include "protocols/packet.h"
#include "protocols/protocol_ids.h"
#include "time/profiler.h"
#include "parser/parser.h"

#include "protocols/ipv4.h"
#include "protocols/ipv6.h"

// Encoder FOO
#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

namespace
{


} // anonymous


#ifdef PERF_PROFILING
THREAD_LOCAL PreprocStats decodePerfStats;
#endif

extern const CodecApi* default_codec;
static const uint16_t max_protocol_id = 65535;
static const uint16_t IP_ID_COUNT = 8192;

// the zero initialization is not required but quiets the compiler
static std::vector<const CodecApi*> s_codecs;
static std::array<uint8_t, max_protocol_id> s_proto_map{{0}};
static std::array<Codec*, UINT8_MAX> s_protocols{{0}};
static THREAD_LOCAL uint8_t grinder = 0;

// Decoding statistics

// this vector reflects the printed names for the statistics
// before the stat_offset
static const std::vector<const char*> stat_names =
{
    "total",
    "other",
    "discards"
};

static const uint8_t total_processed = 0;
static const uint8_t other_codecs = 1;
static const uint8_t discards = 2;
static const uint8_t stat_offset = 3;
static THREAD_LOCAL std::array<PegCount, stat_offset + s_protocols.size()> s_stats{{0}};
static std::array<PegCount, s_stats.size()> g_stats{{0}};

// Encoder Foo
static THREAD_LOCAL rand_t* s_rand = NULL;
static THREAD_LOCAL Packet *encode_pkt;
static THREAD_LOCAL PegCount total_rebuilt_pkts = 0;
static THREAD_LOCAL uint8_t* dst_mac = NULL;
static THREAD_LOCAL std::array<uint16_t, IP_ID_COUNT> s_id_pool{{0}};
static THREAD_LOCAL std::array<uint8_t, Codec::PKT_MAX> s_pkt{{0}};



//-------------------------------------------------------------------------
// Private helper functions
//-------------------------------------------------------------------------


static inline void push_layer(Packet *p,
                                uint16_t prot_id,
                                const uint8_t *hdr_start,
                                uint32_t len,
                                Codec *const cd)
{
    if ( p->next_layer < LAYER_MAX )
    {
        Layer& lyr = p->layers[p->next_layer++];
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

static inline uint8_t* get_inner_ip_hdr(const Packet *p)
{
    const Layer *layers = p->layers;

    for (int i = p->next_layer-1; i >= 0; i--)
    {
        switch(layers[i].prot_id)
        {
            case ETHERTYPE_IPV4:
            case ETHERTYPE_IPV6:
            case IPPROTO_ID_IPIP:
            case IPPROTO_ID_IPV6:
                return layers[i].start;
            default:
                break;
        }
    }
    return nullptr;
}

static inline int get_inner_ip_lyr(const Packet *p)
{
    const Layer *layers = p->layers;

    for (int i = p->next_layer-1; i >= 0; i--)
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

/*
 * Begin search from index 1.  0 is a special case in that it is the default
 * codec and is actually a duplicate. i.e., we can find the 0 indexed
 * codec somehwere else in the array too.
 *
 * Returns: 0 on failure, induex on success
 */
static inline uint8_t get_codec(const char* keyword)
{
    // starting at 1 since 0 is default
    for ( uint8_t i = 1; s_protocols[i] != 0 && i < UINT8_MAX; i++  )
    {
        const char *name = s_protocols[i]->get_name();
        if ( !strncasecmp(name, keyword, strlen(name)) )
            return i;
    }
    return 0;
}

static const uint8_t* encode_packet(
    EncState* enc, const Packet* p, uint32_t* len)
{
    Buffer obuf;

    obuf.base = s_pkt.data() + s_pkt.size() + 1;
    obuf.off = obuf.end = 0;
    obuf.size = sizeof(s_pkt);

    // setting convenience pointers
    enc->layer = p->next_layer;
    enc->p = p;
    enc->ip_hdr = get_inner_ip_hdr(p);

    if ( ipv4::is_ipv4(*(enc->ip_hdr)))
        enc->ip_len = ipv4::get_pkt_len((IPHdr*) enc->ip_hdr);
    else if ( ipv6::is_ip6_hdr_ver((ipv6::IP6RawHdr*)(enc->ip_hdr)))
        enc->ip_len = sizeof(ipv6::IP6RawHdr);
    else
        enc->ip_hdr = 0;


    const Layer *lyrs = p->layers;
    for(int i = p->next_layer-1; i >= 0; i--)
    {
        // lots of room for improvement
        const Layer *l = &lyrs[i];
        enc->layer--;

        // layer 0 is the data link type and doesn't have a protocol id.
        uint8_t mapped_prot = i ? s_proto_map[l->prot_id] : grinder;
        if (!s_protocols[mapped_prot]->encode(enc, &obuf, l->start))
        {
            *len = 0;
            return nullptr;
        }
    }


    *len = (uint32_t)obuf.end;
    return obuf.base + obuf.off;
}

static inline void accumulate()
{
    static std::mutex stats_mutex;

    stats_mutex.lock();
    sum_stats(&g_stats[0], &s_stats[0], s_stats.size());
    stats_mutex.unlock();
}

static bool api_instantiated(const CodecApi* cd_api)
{
    // all elements initialize to false
    static std::vector<bool> instantiated_api(s_codecs.size());

    std::vector<const CodecApi*>::iterator p =
        std::find(s_codecs.begin(), s_codecs.end(), cd_api);

    if (p == s_codecs.end())
        FatalError("PacketManager:: should never reach this code!!" \
                    "Cannot find Codec %s's api", cd_api->base.name);

    int pos = p - s_codecs.begin();
    if(instantiated_api[pos])
        return true;

    instantiated_api[pos] = true;
    return false;
}
//-------------------------------------------------------------------------
// Initialization and setup
//-------------------------------------------------------------------------


void PacketManager::add_plugin(const CodecApi* api)
{
    if (!api->ctor)
        FatalError("Codec %s: ctor() must be implemented.  Look at the example code for an example.\n",
                        api->base.name);      
    if (!api->dtor)
        FatalError("Codec %s: dtor() must be implemented.  Look at the example code for an example.\n",
                        api->base.name);  

    s_codecs.push_back(api);
}

void PacketManager::release_plugins()
{
    for ( auto* p : s_codecs )
    {
        if(p->gterm)
            p->gterm();

        uint8_t index = get_codec(p->base.name);
        if( index != 0)
        {
            p->dtor(s_protocols[index]);
            s_protocols[index] = nullptr;
        }
    }
    s_codecs.clear();
    s_protocols[0] = nullptr;
}

void PacketManager::instantiate(const CodecApi* cd_api , Module* m, SnortConfig* /*sc*/)
{
    static int codec_id = 1;
    std::vector<uint16_t> ids;

    if (api_instantiated(cd_api)) // automatically marks as instantiated
        return;

    if (codec_id >= UINT8_MAX)
        FatalError("A maximum of 256 codecs can be registered\n");

    // global init here to ensure the global policy has already been configured
    if (cd_api->ginit)
        cd_api->ginit();

    Codec *cd = cd_api->ctor(m);
    cd->get_protocol_ids(ids);
    for (auto id : ids)
    {
        if(s_proto_map[id] != 0)
            WarningMessage("The Codecs %s and %s have both been registered "
                "for protocol_id %d. Codec %s will be used\n",
                s_protocols[s_proto_map[id]]->get_name(), cd->get_name(),
                id, cd->get_name());

        s_proto_map[id] = codec_id;
    }

    s_protocols[codec_id++] = cd;
}

void PacketManager::instantiate()
{
    // hard code the default codec into the zero index
    add_plugin(default_codec);
    instantiate(default_codec, nullptr, nullptr);
    s_protocols[0] = s_protocols[get_codec(default_codec->base.name)];

    // and instantiate every codec which does not have a module
    for (auto p : s_codecs)
        instantiate(p, nullptr, nullptr);
}

void PacketManager::thread_init(void)
{
    for ( auto* p : s_codecs )
        if (p->tinit)
            p->tinit();

    int daq_dlt = DAQ_GetBaseProtocol();
    for(int i = 0; s_protocols[i] != 0; i++)
    {
        Codec *cd = s_protocols[i];
        std::vector<int> data_link_types;

        cd->get_data_link_type(data_link_types);
        for (auto curr_dlt : data_link_types)
        {
           if (curr_dlt == daq_dlt)
           {
                if (grinder != 0)
                    WarningMessage("The Codecs %s and %s have both been registered "
                        "as the raw decoder. Codec %s will be used\n",
                        s_protocols[grinder]->get_name(), cd->get_name(),
                        cd->get_name());

                grinder = i;
            }
        }
    }

    if(!grinder)
        FatalError("PacketManager: Unable to find a Codec with data link type %d!!\n", daq_dlt);

    if ( !ScReadMode() || ScPcapShow() )
        LogMessage("Decoding with %s\n", s_protocols[grinder]->get_name());

    // ENCODER initialization

#ifndef VALGRIND_TESTING
    if ( s_rand ) rand_close(s_rand);

    // rand_open() can yield valgriind errors because the
    // starting seed may come from "random stack contents"
    // (see man 3 dnet)
    s_rand = rand_open();

    if ( !s_rand )
        FatalError("PacketManager::init: rand_open() failed.\n");

    rand_get(s_rand, s_id_pool.data(), s_id_pool.size());
#endif
}

void PacketManager::thread_term()
{
    accumulate(); // statistics

    for ( auto* p : s_codecs )
    {
        if(p->tterm)
            p->tterm();
    }

    if ( s_rand )
    {
        rand_close(s_rand);
        s_rand = NULL;
    }
}

SO_PUBLIC Packet* PacketManager::encode_new ()
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

SO_PUBLIC void PacketManager::encode_delete (Packet* p)
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
    uint8_t mapped_prot = grinder;
    uint16_t prev_prot_id = FINISHED_DECODE;
    uint16_t len, lyr_len;

    PREPROC_PROFILE_START(decodePerfStats);

    // initialize all of the relevent data to decode this packet
    memset(p, 0, PKT_ZERO_LEN);
    p->pkth = pkthdr;
    p->pkt = pkt;
    len = pkthdr->caplen;

    s_stats[total_processed]++;

    // loop until the protocol id is no longer valid
    while(s_protocols[mapped_prot]->decode(pkt, len, p, lyr_len, prot_id))
    {
        // internal statistics and record keeping
        push_layer(p, prev_prot_id, pkt, lyr_len, s_protocols[mapped_prot]);
        s_stats[mapped_prot + stat_offset]++;
        mapped_prot = s_proto_map[prot_id];
        prev_prot_id = prot_id;

        // set for next call
        prot_id = FINISHED_DECODE;
        len -= lyr_len;
        pkt += lyr_len;
        lyr_len = 0;

        // since the IP length and the packet length may not be equal.
        if (p->packet_flags & PKT_NEW_IP_LEN)
        {
            len = p->ip_dsize;
            p->packet_flags &= ~PKT_NEW_IP_LEN;
        }
    }

    // if the final protocol ID is not the default codec, a Codec failed
    if (prev_prot_id != FINISHED_DECODE)
    {
        // if the codec exists, it failed
        if(s_proto_map[prev_prot_id])
            s_stats[discards]++;
        else
            s_stats[other_codecs]++;
    }

    s_stats[mapped_prot + stat_offset]++;
    p->dsize = len;
    p->data = pkt;
    PREPROC_PROFILE_END(decodePerfStats);
}

bool PacketManager::has_codec(uint16_t cd_id)
{
    return s_protocols[cd_id] != 0;
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

SO_PUBLIC const uint8_t* PacketManager::encode_response(
    EncodeType type, EncodeFlags flags, const Packet* p, uint32_t* len,
    const uint8_t* payLoad, uint32_t payLen)
{
    EncState enc;

    enc.type = type;
    enc.flags = flags;

    enc.payLoad = payLoad;
    enc.payLen = payLen;

    enc.ip_hdr = NULL;
    enc.ip_len = 0;
    enc.proto = 0;

    if ( encode_pkt )
        p = encode_pkt;

    return encode_packet(&enc, p, len);
}

//-------------------------------------------------------------------------
// formatters:
// - these packets undergo detection
// - need to set Packet stuff except for frag3 which calls grinder
// - include original options except for frag3 inner ip
// - inner layer header is very similar but payload differs
// - original ttl is always used
//-------------------------------------------------------------------------
SO_PUBLIC int PacketManager::encode_format_with_daq_info (
    EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type,
    const DAQ_PktHdr_t* phdr, uint32_t opaque)
{
    int i;
    Layer* lyr;
    size_t len;
    int num_layers = p->next_layer;
    DAQ_PktHdr_t* pkth = (DAQ_PktHdr_t*)c->pkth;
    uint8_t* pkt = (uint8_t*)c->pkt;

    if ( num_layers <= 0 )
        return -1;

    memset(c, 0, PKT_ZERO_LEN);

    c->raw_ip6h = nullptr;
    c->pkth = pkth;
    c->pkt = pkt;

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
        num_layers = get_inner_ip_lyr(p) + 1;

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

        uint8_t mapped_prot = i ? s_proto_map[lyr->prot_id] : grinder;
        s_protocols[mapped_prot]->format(f, p, c, lyr);
    }

    // setup payload info
    c->next_layer = num_layers;
    c->data = lyr->start + lyr->length;
    len = c->data - c->pkt;

    assert(len < Codec::PKT_MAX - IP_MAXPACKET); // len < ETHERNET_HEADER_LEN + VLAN_HEADER + ETHERNET_MTU

    c->max_dsize = IP_MAXPACKET - len;
    c->proto_bits = p->proto_bits;
    c->packet_flags |= PKT_PSEUDO;
    c->pseudo_type = type;
    c->user_policy_id = p->user_policy_id;  // cooked packet gets same policy as raw

    switch ( type )
    {
        case PSEUDO_PKT_SMB_SEG:
        case PSEUDO_PKT_DCE_SEG:
        case PSEUDO_PKT_DCE_FRAG:
        case PSEUDO_PKT_SMB_TRANS:
            c->packet_flags |= PKT_REASSEMBLED_OLD;
            break;
        default:
            break;
    }

    // setup pkt capture header
    pkth->caplen = len;
    pkth->pktlen = len;
    pkth->ts = p->pkth->ts;

    total_rebuilt_pkts++;  // update local counter
    return 0;
}


#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
SO_PUBLIC int PacketManager::encode_format(EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type)
{
    return encode_format_with_daq_info(f, p, c, type, p->pkth, p->pkth->opaque);
}
#elif defined(HAVE_DAQ_ACQUIRE_WITH_META)
SO_PUBLIC int PacketManager::encode_format(EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type)
{
    return encode_format_with_daq_info(f, p, c, type, nullptr, p->pkth->opaque);
}
#else
SO_PUBLIC int PacketManager::encode_format(EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type)
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

SO_PUBLIC void PacketManager::encode_update (Packet* p)
{
    int i;
    uint32_t len = 0;
    DAQ_PktHdr_t* pkth = (DAQ_PktHdr_t*)p->pkth;

    p->actual_ip_len = 0;
    Layer *lyr = p->layers;

    for ( i = p->next_layer - 1; i >= 0; i-- )
    {
        Layer *l = lyr + i;

        uint8_t mapped_prot = i ? s_proto_map[l->prot_id] : grinder;
        s_protocols[mapped_prot]->update(p, l, &len);
    }
    // see IP6_Update() for an explanation of this ...
    if ( !(p->packet_flags & PKT_MODIFIED)
        || (p->packet_flags & PKT_RESIZED)
    )
        pkth->caplen = pkth->pktlen = len;

    p->packet_flags &= ~PKT_LOGGED;
}

//-------------------------------------------------------------------------
// codec support and statistics
//-------------------------------------------------------------------------

void PacketManager::dump_plugins()
{
    Dumper d("Codecs");

    for ( auto* p : s_codecs )
        d.dump(p->base.name, p->base.version);
}

void PacketManager::dump_stats()
{
    std::vector<const char*> pkt_names;

    // zero out the default codecs
    g_stats[3] = 0;
    g_stats[s_proto_map[FINISHED_DECODE] + stat_offset] = 0;

    for(unsigned int i = 0; i < stat_names.size(); i++)
        pkt_names.push_back(stat_names[i]);

    for(int i = 0; s_protocols[i] != 0; i++)
        pkt_names.push_back(s_protocols[i]->get_name());

    show_percent_stats((PegCount*) &g_stats, &pkt_names[0], (unsigned int) pkt_names.size(),
        "codecs");
}

SO_PUBLIC void PacketManager::encode_set_dst_mac(uint8_t *mac)
{
   dst_mac = mac;
}

SO_PUBLIC uint8_t *PacketManager::encode_get_dst_mac()
{
   return dst_mac;
}

uint64_t PacketManager::get_rebuilt_packet_count(void)
{
    return total_rebuilt_pkts;
}

void PacketManager::encode_set_pkt(Packet* p)
{
    encode_pkt = p;
}
