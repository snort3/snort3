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



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/fpdetect.h"

#include "protocols/ipv6.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "codecs/ip/ipv6_util.h"
#include "framework/codec.h"
#include "stream/stream_api.h"
#include "main/snort.h"
#include "packet_io/active.h"
#include "codecs/ip/cd_ipv6_module.h"
#include "codecs/sf_protocols.h"
#include "protocols/protocol_ids.h"

namespace
{

class Ipv6Codec : public Codec
{
public:
    Ipv6Codec() : Codec(CD_IPV6_NAME){};
    ~Ipv6Codec(){};

    virtual PROTO_ID get_proto_id() { return PROTO_IP6; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual bool encode(EncState*, Buffer* out, const uint8_t* raw_in);
    virtual bool update(Packet*, Layer*, uint32_t* len);
    virtual void format(EncodeFlags, const Packet* p, Packet* c, Layer*);

private:

    static uint8_t RevTTL (const EncState* enc, uint8_t ttl);
    static uint8_t FwdTTL (const EncState* enc, uint8_t ttl);
    static uint8_t GetTTL (const EncState* enc);

};


} // namespace


static inline void IPV6CheckIsatap(const ipv6::IP6RawHdr*, Packet* p);
static inline void IPV6MiscTests(Packet* p);
static void CheckIPV6Multicast(const ipv6::IP6RawHdr*, const Packet* const p);
static inline int CheckTeredoPrefix(const ipv6::IP6RawHdr* const hdr);

/********************************************************************
 *************************   PRIVATE FUNCTIONS **********************
 ********************************************************************/

uint8_t Ipv6Codec::GetTTL (const EncState* enc)
{
    char dir;
    uint8_t ttl;
    int outer = !enc->ip_hdr;

    if ( !enc->p->flow )
        return 0;

    if ( enc->p->packet_flags & PKT_FROM_CLIENT )
        dir = forward(enc) ? SSN_DIR_CLIENT : SSN_DIR_SERVER;
    else
        dir = forward(enc) ? SSN_DIR_SERVER : SSN_DIR_CLIENT;

    // outermost ip is considered to be outer here,
    // even if it is the only ip layer ...
    ttl = stream.get_session_ttl(enc->p->flow, dir, outer);

    // so if we don't get outer, we use inner
    if ( 0 == ttl && outer )
        ttl = stream.get_session_ttl(enc->p->flow, dir, 0);

    return ttl;
}

uint8_t Ipv6Codec::FwdTTL (const EncState* enc, uint8_t ttl)
{
    uint8_t new_ttl = GetTTL(enc);
    if ( !new_ttl )
        new_ttl = ttl;
    return new_ttl;
}

uint8_t Ipv6Codec::RevTTL (const EncState* enc, uint8_t ttl)
{
    uint8_t new_ttl = GetTTL(enc);
    if ( !new_ttl )
        new_ttl = ( MAX_TTL - ttl );
    if ( new_ttl < MIN_TTL )
        new_ttl = MIN_TTL;
    return new_ttl;
}




/********************************************************************
 *************************   CLASS FUNCTIONS ************************
 ********************************************************************/

void Ipv6Codec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_IPV6);
    v.push_back(IPPROTO_ID_IPV6);
}


bool Ipv6Codec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
    Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    const ipv6::IP6RawHdr* ip6h;
    uint32_t payload_len;

    /* lay the IP struct over the raw data */
    ip6h = reinterpret_cast<ipv6::IP6RawHdr*>(const_cast<uint8_t*>(raw_pkt));

    if(raw_len < ipv6::hdr_len())
    {
        if ((p->decode_flags & DECODE__UNSURE_ENCAP) == 0)
            codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED);

        // Taken from prot_ipv4.cc
        codec_events::decoder_event(p, DECODE_IPV6_TUNNELED_IPV4_TRUNCATED);
        goto decodeipv6_fail;
    }


    /* Verify version in IP6 Header agrees */
    if(!is_ip6_hdr_ver(ip6h))
    {
        if ((p->decode_flags & DECODE__UNSURE_ENCAP) == 0)
            codec_events::decoder_event(p, DECODE_IPV6_IS_NOT);

        goto decodeipv6_fail;
    }

#if 0
    // multiple encapsulations are now allowed.  this alert is no longer valid
    if (p->encapsulations)
        codec_events::decoder_alert_encapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION,
                        raw_pkt, raw_len);
#endif


    payload_len = ntohs(ip6h->ip6plen) + ipv6::hdr_len();

    if(payload_len != raw_len)
    {
        if (payload_len > raw_len)
        {
            if ((p->decode_flags & DECODE__UNSURE_ENCAP) == 0)
                codec_events::decoder_event(p, DECODE_IPV6_DGRAM_GT_CAPLEN);

            goto decodeipv6_fail;
        }
    }

    /* Teredo packets should always use the 2001:0000::/32 prefix, or in some
       cases the link-local prefix fe80::/64.
       Source: RFC 4380, section 2.6 & section 5.2.1

       Checking the addresses will save us from numerous false positives
       when UDP clients use 3544 as their ephemeral port, or "Deep Teredo
       Inspection" is turned on.

       If we ever start decoding more than 2 layers of IP in a packet, this
       check against p->proto_bits will need to be refactored. */
    if ((p->proto_bits & PROTO_BIT__TEREDO) && (CheckTeredoPrefix(ip6h) == 0))
    {
        goto decodeipv6_fail;
    }



    /* Remove outer IP options */
    if (p->encapsulations)
    {
        p->ip_options_data = NULL;
        p->ip_options_len = 0;
    }
    p->ip_option_count = 0;

    /* set the real IP length for logging */
    p->proto_bits |= PROTO_BIT__IP;
    // extra ipv6 header will be removed in PacketManager
    const_cast<uint32_t&>(raw_len) = ntohs(ip6h->get_len()) + ipv6::hdr_len();

    // check for isatap before overwriting the ip_api.
    IPV6CheckIsatap(ip6h, p);

    p->ip_api.set(ip6h);

    IPV6MiscTests(p);
    CheckIPV6Multicast(ip6h, p);

    next_prot_id = ip6h->get_next();
    lyr_len = ipv6::hdr_len();
    return true;


decodeipv6_fail:
    /* If this was Teredo, back up and treat the packet as normal UDP. */

    if (p->proto_bits & PROTO_BIT__TEREDO)
    {
        p->proto_bits &= ~PROTO_BIT__TEREDO;

        if ( ScTunnelBypassEnabled(TUNNEL_TEREDO) )
            Active_ClearTunnelBypass();
    }

    return false;
}

static inline void IPV6CheckIsatap(const ipv6::IP6RawHdr* ip6h, Packet* p)
{
    /* Only check for IPv6 over IPv4 */
    if (p->ip_api.is_ip4() && p->ip_api.proto() == IPPROTO_IPV6)
    {
        uint32_t isatap_interface_id = ntohl(ip6h->ip6_src.u6_addr32[2]) & 0xFCFFFFFF;

        /* ISATAP uses address with prefix fe80:0000:0000:0000:0200:5efe or
           fe80:0000:0000:0000:0000:5efe, followed by the IPv4 address. */
        if (isatap_interface_id == 0x00005EFE)
        {
            if (p->ip_api.get_src()->ip32[0] != ip6h->ip6_src.u6_addr32[3])
                codec_events::decoder_event(p, DECODE_IPV6_ISATAP_SPOOF);
        }
    }
}

/* Function: IPV6MiscTests(Packet *p)
 *
 * Purpose: A bunch of IPv6 decoder alerts
 *
 * Arguments: p => the Packet to check
 *
 * Returns: void function
 */
static inline void IPV6MiscTests(Packet* p)
{
    const sfip_t *ip_src = p->ip_api.get_src();
    const sfip_t *ip_dst = p->ip_api.get_dst();
    /*
     * Some IP Header tests
     * Land Attack(same src/dst ip)
     * Loopback (src or dst in 127/8 block)
     * Modified: 2/22/05-man for High Endian Architecture.
     *
     * some points in the code assume an IP of 0.0.0.0 matches anything, but
     * that is not so here.  The sfip_compare makes that assumption for
     * compatibility, but sfip_contains does not.  Hence, sfip_contains
     * is used here in the interrim. */
    if( sfip_contains(ip_src, ip_dst) == SFIP_CONTAINS)
    {
        codec_events::decoder_event(p, DECODE_BAD_TRAFFIC_SAME_SRCDST);
    }

    if(sfip_is_loopback(ip_src) || sfip_is_loopback(ip_dst))
    {
        codec_events::decoder_event(p, DECODE_BAD_TRAFFIC_LOOPBACK);
    }

    /* Other decoder alerts for IPv6 addresses
       Added: 5/24/10 (Snort 2.9.0) */
    if (!sfip_is_set(ip_dst))
    {
        codec_events::decoder_event(p, DECODE_IPV6_DST_ZERO);
    }
}



/* Check for multiple IPv6 Multicast-related alerts */
static void CheckIPV6Multicast(const ipv6::IP6RawHdr* ip6h,
        const Packet* const p)
{
    ipv6::MulticastScope multicast_scope;

    if (ip6h->is_src_multicast())
    {
        codec_events::decoder_event(p, DECODE_IPV6_SRC_MULTICAST);
    }
    if (!ip6h->is_dst_multicast())
    {
        return;
    }

    multicast_scope = ip6h->get_dst_multicast_scope();
    switch (multicast_scope)
    {
        case ipv6::MulticastScope::RESERVED:
        case ipv6::MulticastScope::INTERFACE:
        case ipv6::MulticastScope::LINK:
        case ipv6::MulticastScope::ADMIN:
        case ipv6::MulticastScope::SITE:
        case ipv6::MulticastScope::ORG:
        case ipv6::MulticastScope::GLOBAL:
            break;

        default:
            codec_events::decoder_event(p, DECODE_IPV6_BAD_MULTICAST_SCOPE);
    }

    /* Check against assigned multicast addresses. These are listed at:
       http://www.iana.org/assignments/ipv6-multicast-addresses/    */

    /* Multicast addresses only specify the first 16 and last 40 bits.
       Others should be zero. */
    if ((ip6h->ip6_dst.u6_addr16[1] != 0) ||
        (ip6h->ip6_dst.u6_addr16[2] != 0) ||
        (ip6h->ip6_dst.u6_addr16[3] != 0) ||
        (ip6h->ip6_dst.u6_addr16[4] != 0) ||
        (ip6h->ip6_dst.u6_addr8[10] != 0))
    {
        codec_events::decoder_event(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        return;
    }

    if (ip6h->is_multicast_scope_reserved())
    {
        // Node-local scope
        if ((ip6h->ip6_dst.u6_addr16[1] != 0) ||
            (ip6h->ip6_dst.u6_addr16[2] != 0) ||
            (ip6h->ip6_dst.u6_addr16[3] != 0) ||
            (ip6h->ip6_dst.u6_addr16[4] != 0) ||
            (ip6h->ip6_dst.u6_addr16[5] != 0) ||
            (ip6h->ip6_dst.u6_addr16[6] != 0))
        {

            codec_events::decoder_event(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
        else
        {
            switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
            {
                case 0x00000001: // All Nodes
                case 0x00000002: // All Routers
                case 0x000000FB: // mDNSv6
                    break;
                default:
                    codec_events::decoder_event(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
            }
        }
    }
    else if (ip6h->is_multicast_scope_link())
    {
        // Link-local scope
        switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
        {
            case 0x00000001: // All Nodes
            case 0x00000002: // All Routers
            case 0x00000004: // DVMRP Routers
            case 0x00000005: // OSPFIGP
            case 0x00000006: // OSPFIGP Designated Routers
            case 0x00000007: // ST Routers
            case 0x00000008: // ST Hosts
            case 0x00000009: // RIP Routers
            case 0x0000000A: // EIGRP Routers
            case 0x0000000B: // Mobile-Agents
            case 0x0000000C: // SSDP
            case 0x0000000D: // All PIMP Routers
            case 0x0000000E: // RSVP-ENCAPSULATION
            case 0x0000000F: // UPnP
            case 0x00000012: // VRRP
            case 0x00000016: // All MLDv2-capable routers
            case 0x0000006A: // All-Snoopers
            case 0x0000006B: // PTP-pdelay
            case 0x0000006C: // Saratoga
            case 0x0000006D: // LL-MANET-Routers
            case 0x0000006E: // IGRS
            case 0x0000006F: // iADT Discovery
            case 0x000000FB: // mDNSv6
            case 0x00010001: // Link Name
            case 0x00010002: // All-dhcp-agents
            case 0x00010003: // Link-local Multicast Name Resolution
            case 0x00010004: // DTCP Announcement
                break;
            default:
                if ((ip6h->ip6_dst.u6_addr8[11] == 1) &&
                    (ip6h->ip6_dst.u6_addr8[12] == 0xFF))
                {
                    break; // Solicited-Node Address
                }
                if ((ip6h->ip6_dst.u6_addr8[11] == 2) &&
                    (ip6h->ip6_dst.u6_addr8[12] == 0xFF))
                {
                    break; // Node Information Queries
                }
                codec_events::decoder_event(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if (ip6h->is_multicast_scope_site())
    {
        // Site-local scope
        switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
        {
            case 0x00000002: // All Routers
            case 0x000000FB: // mDNSv6
            case 0x00010003: // All-dhcp-servers
            case 0x00010004: // Deprecated
            case 0x00010005: // SL-MANET-ROUTERS
                break;
            default:
                codec_events::decoder_event(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if ((ip6h->ip6_dst.u6_addr8[1] & 0xF0) == 0)
    {
        // Variable scope
        switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
        {
            case 0x0000000C: // SSDP
            case 0x000000FB: // mDNSv6
            case 0x00000181: // PTP-primary
            case 0x00000182: // PTP-alternate1
            case 0x00000183: // PTP-alternate2
            case 0x00000184: // PTP-alternate3
            case 0x0000018C: // All ACs multicast address
            case 0x00000201: // "rwho" Group (BSD)
            case 0x00000202: // SUN RPC PMAPPROC_CALLIT
            case 0x00000204: // All C1222 Nodes
            case 0x00000300: // Mbus/IPv6
            case 0x00027FFE: // SAPv1 Announcements
            case 0x00027FFF: // SAPv0 Announcements
                break;
            default:
                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00000100) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x00000136))
                {
                    break; // Several addresses assigned in a contiguous block
                }

                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00000140) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x0000014F))
                {
                    break; // EPSON-disc-set
                }

                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00020000) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x00027FFD))
                {
                    break; // Multimedia Conference Calls
                }

                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00011000) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x000113FF))
                {
                    break; // Service Location, Version 2
                }

                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00028000) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x0002FFFF))
                {
                    break; // SAP Dynamic Assignments
                }

                codec_events::decoder_event(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if ((ip6h->ip6_dst.u6_addr8[1] & 0xF0) == 0x30)
    {
        // Source-Specific Multicast block
        if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x40000001) &&
            (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x7FFFFFFF))
        {
            return; // IETF consensus
        }
        else if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x80000000) &&
            (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0xFFFFFFFF))
        {
            return; // Dynamiclly allocated by hosts when needed
        }
        else
        {
            // Other addresses in this block are reserved.
            codec_events::decoder_event(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else
    {
        /* Addresses not listed above are reserved. */
        codec_events::decoder_event(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
    }
}


/* Teredo packets need to have one of their IPs use either the Teredo prefix,
   or a link-local prefix (in the case of Router Solicitation messages) */
static inline int CheckTeredoPrefix(const ipv6::IP6RawHdr* const hdr)
{
    /* Check if src address matches 2001::/32 */
    if ((hdr->ip6_src.u6_addr8[0] == 0x20) &&
        (hdr->ip6_src.u6_addr8[1] == 0x01) &&
        (hdr->ip6_src.u6_addr8[2] == 0x00) &&
        (hdr->ip6_src.u6_addr8[3] == 0x00))
        return 1;

    /* Check if src address matches fe80::/64 */
    if ((hdr->ip6_src.u6_addr8[0] == 0xfe) &&
        (hdr->ip6_src.u6_addr8[1] == 0x80) &&
        (hdr->ip6_src.u6_addr8[2] == 0x00) &&
        (hdr->ip6_src.u6_addr8[3] == 0x00) &&
        (hdr->ip6_src.u6_addr8[4] == 0x00) &&
        (hdr->ip6_src.u6_addr8[5] == 0x00) &&
        (hdr->ip6_src.u6_addr8[6] == 0x00) &&
        (hdr->ip6_src.u6_addr8[7] == 0x00))
        return 1;

    /* Check if dst address matches 2001::/32 */
    if ((hdr->ip6_dst.u6_addr8[0] == 0x20) &&
        (hdr->ip6_dst.u6_addr8[1] == 0x01) &&
        (hdr->ip6_dst.u6_addr8[2] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[3] == 0x00))
        return 1;

    /* Check if dst address matches fe80::/64 */
    if ((hdr->ip6_dst.u6_addr8[0] == 0xfe) &&
        (hdr->ip6_dst.u6_addr8[1] == 0x80) &&
        (hdr->ip6_dst.u6_addr8[2] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[3] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[4] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[5] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[6] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[7] == 0x00))
        return 1;

    /* No Teredo prefix found. */
    return 0;
}

/*
 * Encoders
 */

bool Ipv6Codec::encode(EncState* enc, Buffer* out, const uint8_t* raw_in)
{
    if (!update_buffer(out, sizeof(ipv6::IP6RawHdr)))
        return false;

    const ipv6::IP6RawHdr* hi = reinterpret_cast<const ipv6::IP6RawHdr*>(raw_in);
    ipv6::IP6RawHdr* ho = (ipv6::IP6RawHdr*)(out->base);


    ho->ip6flow = htonl(ntohl(hi->ip6flow) & 0xFFF00000);
    ho->ip6nxt = hi->ip6nxt;

    if ( forward(enc) )
    {
        memcpy(ho->ip6_src.u6_addr8, hi->ip6_src.u6_addr8, sizeof(ho->ip6_src.u6_addr8));
        memcpy(ho->ip6_dst.u6_addr8, hi->ip6_dst.u6_addr8, sizeof(ho->ip6_dst.u6_addr8));

        ho->ip6hops = FwdTTL(enc, hi->ip6hops);
    }
    else
    {
        memcpy(ho->ip6_src.u6_addr8, hi->ip6_dst.u6_addr8, sizeof(ho->ip6_src.u6_addr8));
        memcpy(ho->ip6_dst.u6_addr8, hi->ip6_src.u6_addr8, sizeof(ho->ip6_dst.u6_addr8));

        ho->ip6hops = RevTTL(enc, hi->ip6hops);
    }

    if ( enc->proto )
    {
        ho->ip6nxt = enc->proto;
        enc->proto = 0;
    }
    
    ho->ip6plen = htons((uint16_t)(out->end - sizeof(*ho)));
    return true;
}

bool Ipv6Codec::update(Packet* p, Layer* lyr, uint32_t* len)
{
    ipv6::IP6RawHdr* h = (ipv6::IP6RawHdr*)(lyr->start);
    int i = lyr - p->layers;

    // if we didn't trim payload or format this packet,
    // we may not know the actual lengths because not all
    // extension headers are decoded and we stop at frag6.
    // in such case we do not modify the packet length.
    if ( (p->packet_flags & PKT_MODIFIED)
#ifdef NORMALIZER
        && !(p->packet_flags & PKT_RESIZED)
#endif
    )
    {
        *len = ntohs(h->ip6plen) + sizeof(*h);
    }
    else
    {
        if ( i + 1 == p->num_layers )
            *len += lyr->length + p->dsize;

        // w/o all extension headers, can't use just the
        // fixed ip6 header length so we compute header delta
        else
            *len += lyr[1].start - lyr->start;

        // len includes header, remove for payload
        h->ip6plen = htons((uint16_t)(*len - sizeof(*h)));
    }

    return true;
}

void Ipv6Codec::format(EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    ipv6::IP6RawHdr* ch = reinterpret_cast<ipv6::IP6RawHdr*>(
                            const_cast<uint8_t*>(lyr->start));

    if ( reverse(f) )
    {
        int i = lyr - c->layers;
        ipv6::IP6RawHdr* ph = (ipv6::IP6RawHdr*)p->layers[i].start;

        memcpy(ch->ip6_src.u6_addr8, ph->ip6_dst.u6_addr8, sizeof(ch->ip6_src.u6_addr8));
        memcpy(ch->ip6_dst.u6_addr8, ph->ip6_src.u6_addr8, sizeof(ch->ip6_dst.u6_addr8));
    }
    if ( f & ENC_FLAG_DEF )
    {
        int i = lyr - c->layers;
        if ( i + 1 == p->num_layers )
        {
            uint8_t* b = (uint8_t*)p->ip6_extensions[p->ip6_frag_index].data;
            if ( b ) lyr->length = b - p->layers[i].start;
        }
    }

    // set outer to inner so this will always wind pointing to inner
    c->ip_api.set(ch);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Ipv6Module;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Codec* ctor(Module*)
{
    return new Ipv6Codec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi ipv6_api =
{
    {
        PT_CODEC,
        CD_IPV6_NAME,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor,
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};


const BaseApi* cd_ipv6 = &ipv6_api.base;


