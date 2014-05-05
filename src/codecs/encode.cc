/* $Id: encode.c,v 1.70 2013-07-10 19:27:54 twease Exp $ */
/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

// @file    encode.c
// @author  Russ Combs <rcombs@sourcefire.com>

#include "encode.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "assert.h"
#include "packet_io/sfdaq.h"
#include "sf_iph.h"
#include "snort.h"
#include "stream5/stream_api.h"
#include "encode.h"
#include "sf_protocols.h"
 
#include "protocols/ipv6.h"
#include "protocols/udp.h"
#include "protocols/eth.h"
#include "protocols/gtp.h"
#include "codecs/checksum.h"
 


#define GET_IP_HDR_LEN(h) (((h)->ip_verhl & 0x0f) << 2)
#define GET_TCP_HDR_LEN(h) (((h)->th_offx2 & 0xf0) >> 2)
#define SET_TCP_HDR_LEN(h, n) (h)->th_offx2 = ((n << 2) & 0xF0)

#define MIN_TTL             64
#define MAX_TTL            255

#define ICMP_UNREACH_DATA    8  // (per RFC 792)
#define IP_ID_COUNT       8192

static THREAD_LOCAL uint8_t* dst_mac = NULL;
Packet* encode_pkt = NULL;
uint64_t total_rebuilt_pkts = 0;

//-------------------------------------------------------------------------
// encoders operate layer by layer:
// * base+off is start of packet
// * base+end is start of current layer
// * base+size-1 is last byte of packet (in) / buffer (out)
typedef blob_t Buffer;

typedef enum {
    ENC_OK, ENC_BAD_PROTO, ENC_BAD_OPT, ENC_OVERFLOW
} ENC_STATUS;

typedef struct {
    EncodeType type;
    EncodeFlags flags;

    uint8_t layer;
    const Packet* p;
    uint16_t ip_len;
    uint8_t* ip_hdr;

    const uint8_t* payLoad;
    uint32_t payLen;
    uint8_t proto;

} EncState;

#define FORWARD(e) (e->flags & ENC_FLAG_FWD)
#define REVERSE(f) (!(f & ENC_FLAG_FWD))

// PKT_MAX is sized to ensure that any reassembled packet
// can accommodate a full datagram at innermost layer
// 4 == VLAN_HEADER
#define PKT_MAX (ETHERNET_HEADER_LEN + 4 + ETHERNET_MTU + IP_MAXPACKET)

// all layer encoders look like this:
typedef ENC_STATUS (*Encoder)(EncState*, Buffer* in, Buffer* out);
typedef ENC_STATUS (*Updater)(Packet*, Layer*, uint32_t* len);
typedef void (*Formatter)(EncodeFlags, const Packet* p, Packet* c, Layer*);
// TBD implement other encoder functions

typedef struct {
    Encoder fencode;
    Updater fupdate;
    Formatter fformat;
} EncoderFunctions;

// forward declaration; definition at end of file
// the alternative is to put all the function declarations
// here followed by the static array definition.
extern EncoderFunctions encoders[PROTO_MAX];

static void IpId_Init();
static void IpId_Term();

static const uint8_t* Encode_Packet(
    EncState* enc, const Packet* p, uint32_t* len);

static ENC_STATUS UN6_Encode(EncState*, Buffer*, Buffer*);

//-------------------------------------------------------------------------

static inline PROTO_ID NextEncoder (EncState* enc)
{
    if ( enc->layer < enc->p->next_layer )
    {
        PROTO_ID next = enc->p->layers[enc->layer++].proto;
        if ( next < PROTO_MAX )
        {
            if ( encoders[next].fencode ) return next;
        }
    }
    return PROTO_MAX;
}

//-------------------------------------------------------------------------
// basic setup stuff
//-------------------------------------------------------------------------

void Encode_Init (void)
{
    IpId_Init();
}

void Encode_Term (void)
{
    IpId_Term();
}

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

SO_PUBLIC const uint8_t* Encode_Reject(
    EncodeType type, EncodeFlags flags, const Packet* p, uint32_t* len)
{
    EncState enc;

    enc.type = type;
    enc.flags = flags;

    enc.payLoad = NULL;
    enc.payLen = 0;

    enc.ip_hdr = NULL;
    enc.ip_len = 0;
    enc.proto = 0;

    if ( encode_pkt )
        p = encode_pkt;

    return Encode_Packet(&enc, p, len);
}

SO_PUBLIC const uint8_t* Encode_Response(
    EncodeType type, EncodeFlags flags, const Packet* p, uint32_t* len,
    const uint8_t* payLoad, uint32_t payLen
) {
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

    return Encode_Packet(&enc, p, len);
}

//-------------------------------------------------------------------------
// formatters:
// - these packets undergo detection
// - need to set Packet stuff except for frag3 which calls grinder
// - include original options except for frag3 inner ip
// - inner layer header is very similar but payload differs
// - original ttl is always used
//-------------------------------------------------------------------------
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
SO_PUBLIC int Encode_Format_With_DAQ_Info (
    EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type,
    const DAQ_PktHdr_t* phdr, uint32_t opaque)

#elif defined(HAVE_DAQ_ACQUIRE_WITH_META)
SO_PUBLIC int Encode_Format_With_DAQ_Info (
    EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type,
    uint32_t opaque)
#else
SO_PUBLIC int Encode_Format (EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type)
#endif
{
    DAQ_PktHdr_t* pkth = (DAQ_PktHdr_t*)c->pkth;
    uint8_t* pkt = (uint8_t*)c->pkt;

    int i, next_layer = p->next_layer;
    Layer* lyr;
    size_t len;

    if ( next_layer < 1 ) return -1;

    memset(c, 0, PKT_ZERO_LEN);
    c->raw_ip6h = NULL;

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
#endif

    if ( f & ENC_FLAG_NET )
    {
        for ( i = next_layer-1; i >= 0; i-- )
            if ( p->layers[i].proto == PROTO_IP4
              || p->layers[i].proto == PROTO_IP6
            )
                break;
         if ( i < next_layer ) next_layer = i + 1;
    }
    // copy raw packet data to clone
    lyr = (Layer*)p->layers + next_layer - 1;
    len = lyr->start - p->pkt + lyr->length;

    memcpy((void*)c->pkt, p->pkt, len);

    // set up layers
    for ( i = 0; i < next_layer; i++ )
    {
        const uint8_t* b = c->pkt + (p->layers[i].start - p->pkt);
        lyr = c->layers + i;

        lyr->proto = p->layers[i].proto;
        lyr->length = p->layers[i].length;
        lyr->start = (uint8_t*)b;

        if ( lyr->proto < PROTO_MAX )
            encoders[lyr->proto].fformat(f, p, c, lyr);

#ifdef DEBUG
        else
            FatalError("Encode_New() => unsupported proto = %d\n",
                lyr->proto);
#endif
    }
    c->next_layer = next_layer;

    // setup payload info
    c->data = lyr->start + lyr->length;
    len = c->data - c->pkt;
    assert(len < PKT_MAX - IP_MAXPACKET);
    c->max_dsize = IP_MAXPACKET - len;

    c->proto_bits = p->proto_bits;
    c->packet_flags |= PKT_PSEUDO;
    c->pseudo_type = type;
    UpdateRebuiltPktCount();

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
    pkth->caplen = pkth->pktlen = len;
    pkth->ts = p->pkth->ts;

    // cooked packet gets same policy as raw
    c->user_policy_id = p->user_policy_id;

    if ( !c->max_dsize )
        return -1;

    return 0;
}

//-------------------------------------------------------------------------
// formatters:
// - these packets undergo detection
// - need to set Packet stuff except for frag3 which calls grinder
// - include original options except for frag3 inner ip
// - inner layer header is very similar but payload differs
// - original ttl is always used
//-------------------------------------------------------------------------

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
SO_PUBLIC int Encode_Format (EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type)
{
    return Encode_Format_With_DAQ_Info(f, p, c, type, p->pkth, p->pkth->opaque);
}
#elif defined(HAVE_DAQ_ACQUIRE_WITH_META)
SO_PUBLIC int Encode_Format (EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type)
{
    return Encode_Format_With_DAQ_Info(f, p, c, type, p->pkth->opaque);
}
#endif

//-------------------------------------------------------------------------
// updaters:  these functions set length and checksum fields, only needed
// when a packet is modified.  some packets only have replacements so only
// the checksums need to be updated.  we always set the length rather than
// checking each time if needed.
//-------------------------------------------------------------------------

SO_PUBLIC void Encode_Update (Packet* p)
{
    int i;
    uint32_t len = 0;
    DAQ_PktHdr_t* pkth = (DAQ_PktHdr_t*)p->pkth;

    p->actual_ip_len = 0;

    for ( i = p->next_layer - 1; i >= 0; i-- )
    {
        Layer* lyr = p->layers + i;
        encoders[lyr->proto].fupdate(p, lyr, &len);
    }
    // see IP6_Update() for an explanation of this ...
    if ( !(p->packet_flags & PKT_MODIFIED)
        || (p->packet_flags & PKT_RESIZED)
    )
        pkth->caplen = pkth->pktlen = len;

    p->packet_flags &= ~PKT_LOGGED;
}

//-------------------------------------------------------------------------
// internal packet support
//-------------------------------------------------------------------------

SO_PUBLIC Packet* Encode_New ()
{
    Packet* p = (Packet*)SnortAlloc(sizeof(*p));
    uint8_t* b = (uint8_t*)SnortAlloc(sizeof(*p->pkth) + PKT_MAX + SPARC_TWIDDLE);

    if ( !p || !b )
        FatalError("Encode_New() => Failed to allocate packet\n");

    p->pkth = (DAQ_PktHdr_t*)b;
    b += sizeof(*p->pkth);
    b += SPARC_TWIDDLE;
    p->pkt = b;

    return p;
}

SO_PUBLIC void Encode_Delete (Packet* p)
{
    free((void*)p->pkth);  // cast away const!
    free(p);
}

/* Set the destination MAC address*/
SO_PUBLIC void Encode_SetDstMAC(uint8_t *mac)
{
   dst_mac = mac;
}
//-------------------------------------------------------------------------
// private implementation stuff
//-------------------------------------------------------------------------

static THREAD_LOCAL uint8_t s_pkt[PKT_MAX];

static const uint8_t* Encode_Packet(
    EncState* enc, const Packet* p, uint32_t* len)
{
    Buffer ibuf, obuf;
    ENC_STATUS status = ENC_BAD_PROTO;
    PROTO_ID next;

    ibuf.base = (uint8_t*)p->pkt;
    ibuf.off = ibuf.end = 0;
    ibuf.size = p->pkth->caplen;

    obuf.base = s_pkt;
    obuf.off = obuf.end = 0;
    obuf.size = sizeof(s_pkt);

    enc->layer = 0;
    enc->p = p;

    next = NextEncoder(enc);

    if ( next < PROTO_MAX )
    {
        Encoder e = encoders[next].fencode;
        status = (*e)(enc, &ibuf, &obuf);
    }
    if ( status != ENC_OK || enc->layer != p->next_layer )
    {
        *len = 0;
        return NULL;
    }
    *len = (uint32_t)obuf.end;
    return obuf.base + obuf.off;
}

//-------------------------------------------------------------------------
// ip id considerations:
//
// we use dnet's rand services to generate a vector of random 16-bit values and
// iterate over the vector as IDs are assigned.  when we wrap to the beginning,
// the vector is randomly reordered.
//-------------------------------------------------------------------------

static THREAD_LOCAL rand_t* s_rand = NULL;
static THREAD_LOCAL uint16_t s_id_index = 0;
static THREAD_LOCAL uint16_t s_id_pool[IP_ID_COUNT];

static void IpId_Init (void)
{
#ifndef VALGRIND_TESTING
    if ( s_rand ) rand_close(s_rand);

    // rand_open() can yield valgriind errors because the
    // starting seed may come from "random stack contents"
    // (see man 3 dnet)
    s_rand = rand_open();

    if ( !s_rand )
        FatalError("encode::IpId_Init: rand_open() failed.\n");

    rand_get(s_rand, s_id_pool, sizeof(s_id_pool));
#endif
}

static void IpId_Term (void)
{
    if ( s_rand ) rand_close(s_rand);
    s_rand = NULL;
}

static inline uint16_t IpId_Next ()
{
#if defined(REG_TEST) || defined(VALGRIND_TESTING)
    uint16_t id = htons(s_id_index + 1);
#else
    uint16_t id = s_id_pool[s_id_index];
#endif
    s_id_index = (s_id_index + 1) % IP_ID_COUNT;

#ifndef VALGRIND_TESTING
    if ( !s_id_index )
        rand_shuffle(s_rand, s_id_pool, sizeof(s_id_pool), 1);
#endif
    return id;
}

//-------------------------------------------------------------------------
// ttl considerations:
//
// we try to use the TTL captured for the session by the stream preprocessor
// when the session started.  if that is not available, we use the current
// TTL for forward packets and use (maximum - current) TTL for reverse
// packets.
//
// the reason we don't just force ttl to 255 (max) is to make it look a
// little more authentic.
//
// for reference, flexresp used a const rand >= 64 in both directions (the
// number was determined at startup and never changed); flexresp2 used the
// next higher multiple of 64 in both directions; and react used a const
// 64 in both directions.
//
// note that the ip6 hop limit field is entirely equivalent to the ip4 TTL.
// hop limit is in fact a more accurrate name for the actual usage of this
// field.
//-------------------------------------------------------------------------

static inline uint8_t GetTTL (const EncState* enc)
{
    char dir;
    uint8_t ttl;
    int outer = !enc->ip_hdr;

    if ( !enc->p->flow )
        return 0;

    if ( enc->p->packet_flags & PKT_FROM_CLIENT )
        dir = FORWARD(enc) ? SSN_DIR_CLIENT : SSN_DIR_SERVER;
    else
        dir = FORWARD(enc) ? SSN_DIR_SERVER : SSN_DIR_CLIENT;

    // outermost ip is considered to be outer here,
    // even if it is the only ip layer ...
    ttl = stream.get_session_ttl(enc->p->flow, dir, outer);

    // so if we don't get outer, we use inner
    if ( 0 == ttl && outer )
        ttl = stream.get_session_ttl(enc->p->flow, dir, 0);

    return ttl;
}

static inline uint8_t FwdTTL (const EncState* enc, uint8_t ttl)
{
    uint8_t new_ttl = GetTTL(enc);
    if ( !new_ttl )
        new_ttl = ttl;
    return new_ttl;
}

static inline uint8_t RevTTL (const EncState* enc, uint8_t ttl)
{
    uint8_t new_ttl = GetTTL(enc);
    if ( !new_ttl )
        new_ttl = ( MAX_TTL - ttl );
    if ( new_ttl < MIN_TTL )
        new_ttl = MIN_TTL;
    return new_ttl;
}

//-------------------------------------------------------------------------
// the if in UPDATE_BOUND can be defined out after testing because:
// 1. the packet was already decoded in decode.c so is structurally sound; and
// 2. encode takes at most the same space as decode.
#define UPDATE_BOUND(buf, n) \
    buf->end += n; \
    if ( buf->end > buf->size ) \
        return ENC_OVERFLOW
//-------------------------------------------------------------------------
// BUFLEN
// Get the buffer length for a given protocol
#define BUFF_DIFF(buf, ho) ((uint8_t*)(buf->base+buf->end)-(uint8_t*)ho)

//-------------------------------------------------------------------------
// ethernet
//-------------------------------------------------------------------------

static ENC_STATUS Eth_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    // not raw ip -> encode layer 2
    int raw = ( enc->flags & ENC_FLAG_RAW );

    eth::EtherHdr* hi = (eth::EtherHdr*)enc->p->layers[enc->layer-1].start;
    PROTO_ID next = NextEncoder(enc);

    // if not raw ip AND out buf is empty
    if ( !raw && (out->off == out->end) )
    {
        // for alignment
        out->off = out->end = SPARC_TWIDDLE;
    }
    // if not raw ip OR out buf is not empty
    if ( !raw || (out->off != out->end) )
    {
        // we get here for outer-most layer when not raw ip
        // we also get here for any encapsulated ethernet layer.
        eth::EtherHdr* ho = (eth::EtherHdr*)(out->base + out->end);
        UPDATE_BOUND(out, sizeof(*ho));

        ho->ether_type = hi->ether_type;
        if ( FORWARD(enc) )
        {
            memcpy(ho->ether_src, hi->ether_src, sizeof(ho->ether_src));
            /*If user configured remote MAC address, use it*/
            if (NULL != dst_mac)
                memcpy(ho->ether_dst, dst_mac, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_dst, sizeof(ho->ether_dst));
        }
        else
        {
            memcpy(ho->ether_src, hi->ether_dst, sizeof(ho->ether_src));
            /*If user configured remote MAC address, use it*/
            if (NULL != dst_mac)
                memcpy(ho->ether_dst, dst_mac, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_src, sizeof(ho->ether_dst));
        }
    }
    if ( next < PROTO_MAX )
        return encoders[next].fencode(enc, in, out);

    return ENC_OK;
}

static ENC_STATUS Eth_Update (Packet*, Layer* lyr, uint32_t* len)
{
    *len += lyr->length;
    return ENC_OK;
}

static void Eth_Format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    eth::EtherHdr* ch = (eth::EtherHdr*)lyr->start;
    c->eh = ch;

    if ( REVERSE(f) )
    {
        int i = lyr - c->layers;
        eth::EtherHdr* ph = (eth::EtherHdr*)p->layers[i].start;

        memcpy(ch->ether_dst, ph->ether_src, sizeof(ch->ether_dst));
        memcpy(ch->ether_src, ph->ether_dst, sizeof(ch->ether_src));
    }
}

//-------------------------------------------------------------------------
// VLAN
//-------------------------------------------------------------------------

static void VLAN_Format (EncodeFlags, const Packet*, Packet* c, Layer* lyr)
{
    c->vh = (VlanTagHdr*)lyr->start;
}

//-------------------------------------------------------------------------
// GRE
//-------------------------------------------------------------------------
static void GRE_Format (EncodeFlags, const Packet*, Packet* c, Layer* lyr)
{
    c->greh = (GREHdr*)lyr->start;
}

//-------------------------------------------------------------------------
// IP4
//-------------------------------------------------------------------------

static ENC_STATUS IP4_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int len;
    uint32_t start = out->end;

    IPHdr* hi = (IPHdr*)enc->p->layers[enc->layer-1].start;
    IPHdr* ho = (IPHdr*)(out->base + out->end);
    PROTO_ID next = NextEncoder(enc);
    UPDATE_BOUND(out, sizeof(*ho));

    /* IPv4 encoded header is hardcoded 20 bytes */
    ho->ip_verhl = 0x45;
    ho->ip_off = 0;

    ho->ip_id = IpId_Next();
    ho->ip_tos = hi->ip_tos;
    ho->ip_proto = hi->ip_proto;

    if ( FORWARD(enc) )
    {
        ho->ip_src.s_addr = hi->ip_src.s_addr;
        ho->ip_dst.s_addr = hi->ip_dst.s_addr;

        ho->ip_ttl = FwdTTL(enc, hi->ip_ttl);
    }
    else
    {
        ho->ip_src.s_addr = hi->ip_dst.s_addr;
        ho->ip_dst.s_addr = hi->ip_src.s_addr;

        ho->ip_ttl = RevTTL(enc, hi->ip_ttl);
    }

    enc->ip_hdr = (uint8_t*)hi;
    enc->ip_len = IP_HLEN(hi) << 2;

    if ( next < PROTO_MAX )
    {
        ENC_STATUS err = encoders[next].fencode(enc, in, out);
        if ( ENC_OK != err ) return err;
    }
    if ( enc->proto )
    {
        ho->ip_proto = enc->proto;
        enc->proto = 0;
    }

    len = out->end - start;
    ho->ip_len = htons((uint16_t)len);

    ho->ip_csum = 0;

    /* IPv4 encoded header is hardcoded 20 bytes, we save some
     * cycles and use the literal header size for checksum */

    return ENC_OK;
}

static ENC_STATUS IP4_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    IPHdr* h = (IPHdr*)(lyr->start);
    int i = lyr - p->layers;

    *len += GET_IP_HDR_LEN(h);

    if ( i + 1 == p->next_layer )
    {
        *len += p->dsize;
    }
    h->ip_len = htons((uint16_t)*len);

    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) )
    {
        h->ip_csum = 0;
    }

    return ENC_OK;
}

static void IP4_Format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    // TBD handle nested ip layers
    IPHdr* ch = (IPHdr*)lyr->start;
    c->iph = ch;

    if ( REVERSE(f) )
    {
        int i = lyr - c->layers;
        IPHdr* ph = (IPHdr*)p->layers[i].start;

        ch->ip_src.s_addr = ph->ip_dst.s_addr;
        ch->ip_dst.s_addr = ph->ip_src.s_addr;
    }
    if ( f & ENC_FLAG_DEF )
    {
        int i = lyr - c->layers;
        if ( i + 1 == p->next_layer )
        {
            lyr->length = sizeof(*ch);
            ch->ip_len = htons(lyr->length);
            SET_IP_HLEN(ch, lyr->length >> 2);
        }
    }
    sfiph_build(c, c->iph, AF_INET);
}

//-------------------------------------------------------------------------
// ICMP
// UNR encoder creates ICMP unreachable
//-------------------------------------------------------------------------

static inline int IcmpCode (EncodeType et) {
    switch ( et ) {
    case ENC_UNR_NET:  return ICMP_UNREACH_NET;
    case ENC_UNR_HOST: return ICMP_UNREACH_HOST;
    case ENC_UNR_PORT: return ICMP_UNREACH_PORT;
    case ENC_UNR_FW:   return ICMP_UNREACH_FILTER_PROHIB;
    default: break;
    }
    return ICMP_UNREACH_PORT;
}

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint32_t unused;
} IcmpHdr;

static ENC_STATUS UN4_Encode (EncState* enc, Buffer*, Buffer* out)
{
    uint8_t* p;

    uint8_t* hi = enc->p->layers[enc->layer-1].start;
    IcmpHdr* ho = (IcmpHdr*)(out->base + out->end);

#ifdef DEBUG
    if ( enc->type < ENC_UNR_NET )
        return ENC_BAD_OPT;
#endif

    enc->proto = IPPROTO_ICMP;

    UPDATE_BOUND(out, sizeof(*ho));
    ho->type = ICMP_UNREACH;
    ho->code = IcmpCode(enc->type);
    ho->cksum = 0;
    ho->unused = 0;

    // copy original ip header
    p = out->base + out->end;
    UPDATE_BOUND(out, enc->ip_len);
    memcpy(p, enc->ip_hdr, enc->ip_len);

    // copy first 8 octets of original ip data (ie udp header)
    p = out->base + out->end;
    UPDATE_BOUND(out, ICMP_UNREACH_DATA);
    memcpy(p, hi, ICMP_UNREACH_DATA);


    return ENC_OK;
}

static ENC_STATUS ICMP4_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    IcmpHdr* h = (IcmpHdr*)(lyr->start);

    *len += sizeof(*h) + p->dsize;


    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        h->cksum = 0;
    }

    return ENC_OK;
}

static void ICMP4_Format (EncodeFlags, const Packet*, Packet* c, Layer* lyr)
{
    // TBD handle nested icmp4 layers
    c->icmph = (ICMPHdr*)lyr->start;
}

//-------------------------------------------------------------------------
// UDP
//-------------------------------------------------------------------------

static ENC_STATUS UDP_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    PROTO_ID next = PROTO_MAX;

    if ( enc->layer < enc->p->next_layer )
    {
        next = enc->p->layers[enc->layer].proto;
    }
    if ((PROTO_GTP == next) && (encoders[next].fencode))
    {
        int len;
        ENC_STATUS err;
        uint32_t start = out->end;

        udp::UDPHdr* hi = (udp::UDPHdr*)enc->p->layers[enc->layer-1].start;
        udp::UDPHdr* ho = (udp::UDPHdr*)(out->base + out->end);
        UPDATE_BOUND(out, sizeof(*ho));

        if ( FORWARD(enc) )
        {
            ho->uh_sport = hi->uh_sport;
            ho->uh_dport = hi->uh_dport;
        }
        else
        {
            ho->uh_sport = hi->uh_dport;
            ho->uh_dport = hi->uh_sport;
        }

        next = NextEncoder(enc);
        err = encoders[next].fencode(enc, in, out);
        if (ENC_OK != err ) return err;
        len = out->end - start;
        ho->uh_len = htons((uint16_t)len);

        ho->uh_chk = 0;

#if 0  // FIXIT - unused pseudo headers
        if (IP_VER((IPHdr *)enc->ip_hdr) == 4) {
            pseudoheader ps;
            ps.sip = ((IPHdr *)enc->ip_hdr)->ip_src.s_addr;
            ps.dip = ((IPHdr *)enc->ip_hdr)->ip_dst.s_addr;
            ps.zero = 0;
            ps.protocol = IPPROTO_UDP;
            ps.len = ho->uh_len;
        }
        else {
            pseudoheader6 ps6;
            memcpy(ps6.sip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_src.s6_addr, sizeof(ps6.sip));
            memcpy(ps6.dip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_dst.s6_addr, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_UDP;
            ps6.len = ho->uh_len;
        }
#endif

        return ENC_OK;
    }
    if ( IP_VER((IPHdr*)enc->ip_hdr) == 4 )
        return UN4_Encode(enc, in, out);

    return UN6_Encode(enc, in, out);
}

static ENC_STATUS UDP_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    udp::UDPHdr* h = (udp::UDPHdr*)(lyr->start);

    *len += sizeof(*h) + p->dsize;
    h->uh_len = htons((uint16_t)*len);


    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        h->uh_chk = 0;

#if 0  // FIXIT - unused pseudo headers
        if (IS_IP4(p)) {
            pseudoheader ps;
            ps.sip = ((IPHdr *)(lyr-1)->start)->ip_src.s_addr;
            ps.dip = ((IPHdr *)(lyr-1)->start)->ip_dst.s_addr;
            ps.zero = 0;
            ps.protocol = IPPROTO_UDP;
            ps.len = htons((uint16_t)*len);
        } else {
            pseudoheader6 ps6;
            memcpy(ps6.sip, &p->ip6h->ip_src.ip32, sizeof(ps6.sip));
            memcpy(ps6.dip, &p->ip6h->ip_dst.ip32, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_UDP;
            ps6.len = htons((uint16_t)*len);
        }
#endif
    }

    return ENC_OK;
}

static void UDP_Format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    udp::UDPHdr* ch = (udp::UDPHdr*)lyr->start;
    c->udph = ch;

    if ( REVERSE(f) )
    {
        int i = lyr - c->layers;
        udp::UDPHdr* ph = (udp::UDPHdr*)p->layers[i].start;

        ch->uh_sport = ph->uh_dport;
        ch->uh_dport = ph->uh_sport;
    }
    c->sp = ntohs(ch->uh_sport);
    c->dp = ntohs(ch->uh_dport);
}

//-------------------------------------------------------------------------
// TCP
// encoder creates TCP RST
// should always try to use acceptable ack since we send RSTs in a
// stateless fashion ... from rfc 793:
//
// In all states except SYN-SENT, all reset (RST) segments are validated
// by checking their SEQ-fields.  A reset is valid if its sequence number
// is in the window.  In the SYN-SENT state (a RST received in response
// to an initial SYN), the RST is acceptable if the ACK field
// acknowledges the SYN.
//-------------------------------------------------------------------------

static ENC_STATUS TCP_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int len, ctl;

    TCPHdr* hi = (TCPHdr*)enc->p->layers[enc->layer-1].start;
    TCPHdr* ho = (TCPHdr*)(out->base + out->end);

    UPDATE_BOUND(out, sizeof(*ho));

    len = GET_TCP_HDR_LEN(hi) - sizeof(*hi);
    UPDATE_BOUND(in, len);
    ctl = (hi->th_flags & TH_SYN) ? 1 : 0;

    if ( FORWARD(enc) )
    {
        ho->th_sport = hi->th_sport;
        ho->th_dport = hi->th_dport;

        // th_seq depends on whether the data passes or drops
        if ( DAQ_GetInterfaceMode(enc->p->pkth) != DAQ_MODE_INLINE )
            ho->th_seq = htonl(ntohl(hi->th_seq) + enc->p->dsize + ctl);
        else
            ho->th_seq = hi->th_seq;

        ho->th_ack = hi->th_ack;
    }
    else
    {
        ho->th_sport = hi->th_dport;
        ho->th_dport = hi->th_sport;

        ho->th_seq = hi->th_ack;
        ho->th_ack = htonl(ntohl(hi->th_seq) + enc->p->dsize + ctl);
    }

    if ( enc->flags & ENC_FLAG_SEQ )
    {
        uint32_t seq = ntohl(ho->th_seq);
        seq += (enc->flags & ENC_FLAG_VAL);
        ho->th_seq = htonl(seq);
    }
    ho->th_offx2 = 0;
    SET_TCP_OFFSET(ho, (TCP_HDR_LEN >> 2));
    ho->th_win = ho->th_urp = 0;

    if ( enc->type == ENC_TCP_FIN || enc->type == ENC_TCP_PUSH )
    {
        if ( enc->payLoad && enc->payLen > 0 )
        {
            uint8_t* pdu = out->base + out->end;
            UPDATE_BOUND(out, enc->payLen);
            memcpy(pdu, enc->payLoad, enc->payLen);
        }

        ho->th_flags = TH_ACK;
        if ( enc->type == ENC_TCP_PUSH )
        {
            ho->th_flags |= TH_PUSH;
            ho->th_win = htons(65535);
        }
        else
        {
            ho->th_flags |= TH_FIN;
        }
    }
    else
    {
        ho->th_flags = TH_RST | TH_ACK;
    }

    // in case of ip6 extension headers, this gets next correct
    enc->proto = IPPROTO_TCP;

    ho->th_sum = 0;

#if 0  // FIXIT - unused pseudo headers
    if (IP_VER((IPHdr *)enc->ip_hdr) == 4) {
        pseudoheader ps;
        int len = BUFF_DIFF(out, ho);

        ps.sip = ((IPHdr *)(enc->ip_hdr))->ip_src.s_addr;
        ps.dip = ((IPHdr *)(enc->ip_hdr))->ip_dst.s_addr;
        ps.zero = 0;
        ps.protocol = IPPROTO_TCP;
        ps.len = htons((uint16_t)len);
    } else {
        pseudoheader6 ps6;
        int len = BUFF_DIFF(out, ho);

        memcpy(ps6.sip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_src.s6_addr, sizeof(ps6.sip));
        memcpy(ps6.dip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_dst.s6_addr, sizeof(ps6.dip));
        ps6.zero = 0;
        ps6.protocol = IPPROTO_TCP;
        ps6.len = htons((uint16_t)len);
    }
#endif

    return ENC_OK;
}

static ENC_STATUS TCP_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    TCPHdr* h = (TCPHdr*)(lyr->start);

    *len += GET_TCP_HDR_LEN(h) + p->dsize;

    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        h->th_sum = 0;

#if 0  // FIXIT - unused pseudo headers
        if (IS_IP4(p)) {
            pseudoheader ps;
            ps.sip = ((IPHdr *)(lyr-1)->start)->ip_src.s_addr;
            ps.dip = ((IPHdr *)(lyr-1)->start)->ip_dst.s_addr;
            ps.zero = 0;
            ps.protocol = IPPROTO_TCP;
            ps.len = htons((uint16_t)*len);
        } else {
            pseudoheader6 ps6;
            memcpy(ps6.sip, &p->ip6h->ip_src.ip32, sizeof(ps6.sip));
            memcpy(ps6.dip, &p->ip6h->ip_dst.ip32, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_TCP;
            ps6.len = htons((uint16_t)*len);
        }
#endif
    }

    return ENC_OK;
}

static void TCP_Format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    TCPHdr* ch = (TCPHdr*)lyr->start;
    c->tcph = ch;

    if ( REVERSE(f) )
    {
        int i = lyr - c->layers;
        TCPHdr* ph = (TCPHdr*)p->layers[i].start;

        ch->th_sport = ph->th_dport;
        ch->th_dport = ph->th_sport;
    }
    c->sp = ntohs(ch->th_sport);
    c->dp = ntohs(ch->th_dport);
}

//-------------------------------------------------------------------------
// IP6 encoder
//-------------------------------------------------------------------------

static ENC_STATUS IP6_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int len;
    uint32_t start = out->end;

    ipv6::IP6RawHdr* hi = (ipv6::IP6RawHdr*)enc->p->layers[enc->layer-1].start;
    ipv6::IP6RawHdr* ho = (ipv6::IP6RawHdr*)(out->base + out->end);
    PROTO_ID next = NextEncoder(enc);

    UPDATE_BOUND(out, sizeof(*ho));

    ho->ip6flow = htonl(ntohl(hi->ip6flow) & 0xFFF00000);
    ho->ip6nxt = hi->ip6nxt;

    if ( FORWARD(enc) )
    {
        memcpy(ho->ip6_src.s6_addr, hi->ip6_src.s6_addr, sizeof(ho->ip6_src.s6_addr));
        memcpy(ho->ip6_dst.s6_addr, hi->ip6_dst.s6_addr, sizeof(ho->ip6_dst.s6_addr));

        ho->ip6hops = FwdTTL(enc, hi->ip6hops);
    }
    else
    {
        memcpy(ho->ip6_src.s6_addr, hi->ip6_dst.s6_addr, sizeof(ho->ip6_src.s6_addr));
        memcpy(ho->ip6_dst.s6_addr, hi->ip6_src.s6_addr, sizeof(ho->ip6_dst.s6_addr));

        ho->ip6hops = RevTTL(enc, hi->ip6hops);
    }

    enc->ip_hdr = (uint8_t*)hi;
    enc->ip_len = sizeof(*hi);

    if ( next < PROTO_MAX )
    {
        ENC_STATUS err = encoders[next].fencode(enc, in, out);
        if ( ENC_OK != err ) return err;
    }
    if ( enc->proto )
    {
        ho->ip6nxt = enc->proto;
        enc->proto = 0;
    }
    len = out->end - start;
    ho->ip6plen = htons((uint16_t)(len - sizeof(*ho)));

    return ENC_OK;
}

static ENC_STATUS IP6_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    ipv6::IP6RawHdr* h = (ipv6::IP6RawHdr*)(lyr->start);
    int i = lyr - p->layers;

    // if we didn't trim payload or format this packet,
    // we may not know the actual lengths because not all
    // extension headers are decoded and we stop at frag6.
    // in such case we do not modify the packet length.
    if ( (p->packet_flags & PKT_MODIFIED)
        && !(p->packet_flags & PKT_RESIZED)
    ) {
        *len = ntohs(h->ip6plen) + sizeof(*h);
    }
    else
    {
        if ( i + 1 == p->next_layer )
            *len += lyr->length + p->dsize;

        // w/o all extension headers, can't use just the
        // fixed ip6 header length so we compute header delta
        else
            *len += lyr[1].start - lyr->start;

        // len includes header, remove for payload
        h->ip6plen = htons((uint16_t)(*len - sizeof(*h)));
    }

    return ENC_OK;
}

static void IP6_Format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    ipv6::IP6RawHdr* ch = (ipv6::IP6RawHdr*)lyr->start;

    if ( REVERSE(f) )
    {
        int i = lyr - c->layers;
        ipv6::IP6RawHdr* ph = (ipv6::IP6RawHdr*)p->layers[i].start;

        memcpy(ch->ip6_src.s6_addr, ph->ip6_dst.s6_addr, sizeof(ch->ip6_src.s6_addr));
        memcpy(ch->ip6_dst.s6_addr, ph->ip6_src.s6_addr, sizeof(ch->ip6_dst.s6_addr));
    }
    if ( f & ENC_FLAG_DEF )
    {
        int i = lyr - c->layers;
        if ( i + 1 == p->next_layer )
        {
            uint8_t* b = (uint8_t*)p->ip6_extensions[p->ip6_frag_index].data;
            if ( b ) lyr->length = b - p->layers[i].start;
        }
    }
    sfiph_build(c, ch, AF_INET6);

    // set outer to inner so this will always wind pointing to inner
    c->raw_ip6h = ch;
}

//-------------------------------------------------------------------------
// IP6 options functions
//-------------------------------------------------------------------------

static ENC_STATUS Opt6_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    // we don't encode ext headers
    PROTO_ID next = NextEncoder(enc);

    if ( next < PROTO_MAX )
    {
        ENC_STATUS err = encoders[next].fencode(enc, in, out);
        if ( ENC_OK != err ) return err;
    }
    return ENC_OK;
}

static ENC_STATUS Opt6_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    int i = lyr - p->layers;
    *len += lyr->length;

    if ( i + 1 == p->next_layer )
        *len += p->dsize;

    return ENC_OK;
}

//-------------------------------------------------------------------------
// ICMP6 functions
//-------------------------------------------------------------------------

static ENC_STATUS UN6_Encode (EncState* enc, Buffer*, Buffer* out)
{
    uint8_t* p;
    uint8_t* hi = enc->p->layers[enc->layer-1].start;
    IcmpHdr* ho = (IcmpHdr*)(out->base + out->end);
    checksum::Pseudoheader6 ps6;
    int len;

#ifdef DEBUG
    if ( enc->type < ENC_UNR_NET )
        return ENC_BAD_OPT;
#endif

    enc->proto = IPPROTO_ICMPV6;

    UPDATE_BOUND(out, sizeof(*ho));
    ho->type = 1;   // dest unreachable
    ho->code = 4;   // port unreachable
    ho->cksum = 0;
    ho->unused = 0;

    // ip + udp headers are copied separately because there
    // may be intervening extension headers which aren't copied

    // copy original ip header
    p = out->base + out->end;
    UPDATE_BOUND(out, enc->ip_len);
    // TBD should be able to elminate enc->ip_hdr by using layer-2
    memcpy(p, enc->ip_hdr, enc->ip_len);
    ((ipv6::IP6RawHdr*)p)->ip6nxt = IPPROTO_UDP;

    // copy first 8 octets of original ip data (ie udp header)
    // TBD: copy up to minimum MTU worth of data
    p = out->base + out->end;
    UPDATE_BOUND(out, ICMP_UNREACH_DATA);
    memcpy(p, hi, ICMP_UNREACH_DATA);

    len = BUFF_DIFF(out, ho);

    memcpy(ps6.sip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_src.s6_addr, sizeof(ps6.sip));
    memcpy(ps6.dip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_dst.s6_addr, sizeof(ps6.dip));
    ps6.zero = 0;
    ps6.protocol = IPPROTO_ICMPV6;
    ps6.len = htons((uint16_t)(len));


    return ENC_OK;
}

static ENC_STATUS ICMP6_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    IcmpHdr* h = (IcmpHdr*)(lyr->start);

    *len += sizeof(*h) + p->dsize;

    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        checksum::Pseudoheader6 ps6;
        h->cksum = 0;

        memcpy(ps6.sip, &p->ip6h->ip_src.ip32, sizeof(ps6.sip));
        memcpy(ps6.dip, &p->ip6h->ip_dst.ip32, sizeof(ps6.dip));
        ps6.zero = 0;
        ps6.protocol = IPPROTO_ICMPV6;
        ps6.len = htons((uint16_t)*len);
    }

    return ENC_OK;
}

static void ICMP6_Format (EncodeFlags, const Packet*, Packet* c, Layer* lyr)
{
    // TBD handle nested icmp6 layers
    c->icmp6h = (ICMP6Hdr*)lyr->start;
}

//-------------------------------------------------------------------------
// GTP functions
//-------------------------------------------------------------------------

static ENC_STATUS update_GTP_length(GTPHdr* h, int gtp_total_len )
{
    /*The first 3 bits are version number*/
    uint8_t version = (h->flag & 0xE0) >> 5;
    switch (version)
    {
    case 0: /*GTP v0*/
        h->length = htons((uint16_t)(gtp_total_len - gtp::v0_hdr_len()));
        break;
    case 1: /*GTP v1*/
        h->length = htons((uint16_t)(gtp_total_len - gtp::min_hdr_len()));
        break;
    default:
        return ENC_BAD_PROTO;
    }
    return ENC_OK;

}

static ENC_STATUS GTP_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int n = enc->p->layers[enc->layer-1].length;
    int len;

    GTPHdr* hi = (GTPHdr*) (enc->p->layers[enc->layer-1].start);
    GTPHdr* ho = (GTPHdr*)(out->base + out->end);
    uint32_t start = out->end;
    PROTO_ID next = NextEncoder(enc);

    UPDATE_BOUND(out, n);
    memcpy(ho, hi, n);

    if ( next < PROTO_MAX )
    {
        ENC_STATUS err = encoders[next].fencode(enc, in, out);
        if (ENC_OK != err ) return err;
    }
    len = out->end - start;
    return( update_GTP_length(ho,len));
}

static ENC_STATUS GTP_Update (Packet*, Layer* lyr, uint32_t* len)
{
    GTPHdr* h = (GTPHdr*)(lyr->start);
    *len += lyr->length;
    return( update_GTP_length(h,*len));
}

//-------------------------------------------------------------------------
// PPPoE functions
//-------------------------------------------------------------------------

static ENC_STATUS PPPoE_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int n = enc->p->layers[enc->layer-1].length;
    int len;

    PPPoEHdr* hi = (PPPoEHdr*)(enc->p->layers[enc->layer-1].start);
    PPPoEHdr* ho = (PPPoEHdr*)(out->base + out->end);

    uint32_t start;
    PROTO_ID next = NextEncoder(enc);

    UPDATE_BOUND(out, n);
    memcpy(ho, hi, n);

    start = out->end;

    if ( next < PROTO_MAX )
    {
        ENC_STATUS err = encoders[next].fencode(enc, in, out);
        if (ENC_OK != err ) return err;
    }
    len = out->end - start;
    ho->length = htons((uint16_t)len);

    return ENC_OK;
}

//-------------------------------------------------------------------------
// XXX (generic) functions
//-------------------------------------------------------------------------

static ENC_STATUS XXX_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int n = enc->p->layers[enc->layer-1].length;

    uint8_t* hi = enc->p->layers[enc->layer-1].start;
    uint8_t* ho = (uint8_t*)(out->base + out->end);
    PROTO_ID next = NextEncoder(enc);

    UPDATE_BOUND(out, n);
    memcpy(ho, hi, n);

    if ( next < PROTO_MAX )
    {
        ENC_STATUS err = encoders[next].fencode(enc, in, out);
        if (ENC_OK != err ) return err;
    }
    return ENC_OK;
}

// for general cases, may need to move dsize out of top, tcp, and
// udp and put in Encode_Update() (then this can be eliminated and
// xxx called instead).  (another thought is to add data as a "layer").

#if 0
static ENC_STATUS Top_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    *len += lyr->length + p->dsize;
    return ENC_OK;
}
#endif

static ENC_STATUS XXX_Update (Packet*, Layer* lyr, uint32_t* len)
{
    *len += lyr->length;
    return ENC_OK;
}

static void XXX_Format (EncodeFlags, const Packet*, Packet*, Layer*)
{
    // nop
}

//-------------------------------------------------------------------------
// function table:
// these must be in the same order PROTO_IDs are defined!
// all entries must have a function
//-------------------------------------------------------------------------

EncoderFunctions encoders[PROTO_MAX] = {  // FIXIT should be static
    { Eth_Encode,  Eth_Update,   Eth_Format   },
    { IP4_Encode,  IP4_Update,   IP4_Format   },
    { UN4_Encode,  ICMP4_Update, ICMP4_Format },
    { XXX_Encode,  XXX_Update,   XXX_Format,  },  // ICMP_IP4
    { UDP_Encode,  UDP_Update,   UDP_Format   },
    { TCP_Encode,  TCP_Update,   TCP_Format   },
    { IP6_Encode,  IP6_Update,   IP6_Format   },
    { Opt6_Encode, Opt6_Update,  XXX_Format   },  // IP6 Hop Opts
    { Opt6_Encode, Opt6_Update,  XXX_Format   },  // IP6 Dst Opts
    { UN6_Encode,  ICMP6_Update, ICMP6_Format },
    { XXX_Encode,  XXX_Update,   XXX_Format,  },  // ICMP_IP6
    { XXX_Encode,  XXX_Update,   VLAN_Format  },
    { XXX_Encode,  XXX_Update,   GRE_Format   },
    { XXX_Encode,  XXX_Update,   XXX_Format   },  // ERSPAN
    { PPPoE_Encode,XXX_Update,   XXX_Format   },
    { XXX_Encode,  XXX_Update,   XXX_Format   },  // PPP Encap
    { XXX_Encode,  XXX_Update,   XXX_Format   },  // MPLS
    { XXX_Encode,  XXX_Update,   XXX_Format,  },  // ARP
    { GTP_Encode,  GTP_Update,   XXX_Format,  },  // GTP
    { XXX_Encode,  XXX_Update,   XXX_Format,  }   // Auth Header
};

