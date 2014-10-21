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
// cd_ipv4.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <array>
#include "utils/dnet_header.h"
#include "main/snort.h"
#include "fpdetect.h"


#include "protocols/tcp.h"
#include "protocols/ipv4.h"
#include "protocols/packet_manager.h"

#include "utils/stats.h"
#include "packet_io/active.h"
#include "codecs/codec_events.h"
#include "codecs/ip/checksum.h"
#include "main/thread.h"
#include "stream/stream_api.h"
#include "codecs/decode_module.h"
#include "protocols/ip.h"
#include "protocols/ipv4_options.h"
#include "log/text_log.h"
#include "log/log_text.h"

#define CD_IPV4_NAME "ipv4"
#define CD_IPV4_HELP "support for Internet protocol v4"

namespace{

static const RuleMap ipv4_rules[] =
{
    { DECODE_NOT_IPV4_DGRAM, "Not IPv4 datagram" },
    { DECODE_IPV4_INVALID_HEADER_LEN, "hlen < minimum" },
    { DECODE_IPV4_DGRAM_LT_IPHDR, "IP dgm len < IP Hdr len" },
    { DECODE_IPV4OPT_BADLEN, "Ipv4 Options found with bad lengths" },
    { DECODE_IPV4OPT_TRUNCATED, "Truncated Ipv4 Options" },
    { DECODE_IPV4_DGRAM_GT_CAPLEN, "IP dgm len > captured len" },
    { DECODE_ZERO_TTL, "IPV4 packet with zero TTL" },
    { DECODE_BAD_FRAGBITS, "IPV4 packet with bad frag bits (both MF and DF set)" },
    { DECODE_IP4_LEN_OFFSET, "IPV4 packet frag offset + length exceed maximum" },
    { DECODE_IP4_SRC_THIS_NET, "IPV4 packet from 'current net' source address" },
    { DECODE_IP4_DST_THIS_NET, "IPV4 packet to 'current net' dest address" },
    { DECODE_IP4_SRC_MULTICAST, "IPV4 packet from multicast source address" },
    { DECODE_IP4_SRC_RESERVED, "IPV4 packet from reserved source address" },
    { DECODE_IP4_DST_RESERVED, "IPV4 packet to reserved dest address" },
    { DECODE_IP4_SRC_BROADCAST, "IPV4 packet from broadcast source address" },
    { DECODE_IP4_DST_BROADCAST, "IPV4 packet to broadcast dest address" },
    { DECODE_IP4_MIN_TTL, "IPV4 packet below TTL limit" },
    { DECODE_IP4_DF_OFFSET, "IPV4 packet both DF and offset set" },
    { DECODE_IP_RESERVED_FRAG_BIT, "BAD-TRAFFIC IP reserved bit set" },
    { DECODE_IP_UNASSIGNED_PROTO, "BAD-TRAFFIC unassigned/reserved IP protocol" },
    { DECODE_IP_BAD_PROTO, "BAD-TRAFFIC bad IP protocol" },
    { DECODE_IP_OPTION_SET, "MISC IP option set" },
    { DECODE_IP_MULTIPLE_ENCAPSULATION, "two or more IP (v4 and/or v6) encapsulation layers present" },
    { DECODE_ZERO_LENGTH_FRAG, "fragment with zero length" },
    { DECODE_IP4_HDR_TRUNC, "truncated IP4 header" },
    { DECODE_BAD_TRAFFIC_LOOPBACK, "bad traffic loopback IP" },
    { DECODE_BAD_TRAFFIC_SAME_SRCDST, "bad traffic same src/dst IP" },
    { 0, nullptr }
};

class Ipv4Module : public DecodeModule
{
public:
    Ipv4Module() : DecodeModule(CD_IPV4_NAME, CD_IPV4_HELP) {}

    const RuleMap* get_rules() const
    { return ipv4_rules; }
};

class Ipv4Codec : public Codec
{
public:
    Ipv4Codec() : Codec(CD_IPV4_NAME){};
    ~Ipv4Codec(){};

    void get_protocol_ids(std::vector<uint16_t>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* /*raw_pkt*/,
        const Packet* const) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
                        EncState&, Buffer&) override;
    bool update(Packet*, Layer*, uint32_t* len) override;
    void format(EncodeFlags, const Packet* p, Packet* c, Layer*) override;

};

/* Last updated 5/2/2014.
   Source: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml */
const uint16_t MIN_UNASSIGNED_IP_PROTO = 143;

const uint16_t IP_ID_COUNT = 8192;
static THREAD_LOCAL rand_t* s_rand = 0;
static THREAD_LOCAL uint16_t s_id_index = 0;
static THREAD_LOCAL std::array<uint16_t, IP_ID_COUNT> s_id_pool{{0}};

}  // namespace


static inline void IP4AddrTests(const IP4Hdr*, const CodecData&);
static inline void IPMiscTests(const IP4Hdr* const ip4h, const CodecData& codec, uint16_t len);
static void DecodeIPOptions(const uint8_t *start, uint8_t& o_len, CodecData& data);



void Ipv4Codec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_IPV4);
    v.push_back(IPPROTO_ID_IPIP);
}


bool Ipv4Codec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    uint32_t ip_len; /* length from the start of the ip hdr to the pkt end */
    uint16_t hlen;  /* ip header length */

    /* do a little validation */
    if(raw.len < ip::IP4_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated IP4 header (%d bytes).\n", raw.len););

        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_events::decoder_event(codec, DECODE_IP4_HDR_TRUNC);
        return false;
    }


    if (++codec.ip_layer_cnt > snort_conf->get_ip_maxlayers())
        codec_events::decoder_event(codec, DECODE_IP_MULTIPLE_ENCAPSULATION);

    /* lay the IP struct over the raw data */
    const IP4Hdr* const iph = reinterpret_cast<const IP4Hdr*>(raw.data);

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if (iph->get_ver() != 4)
    {
        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_events::decoder_event(codec, DECODE_NOT_IPV4_DGRAM);
        return false;
    }

    /* get the IP datagram length */
    ip_len = ntohs(iph->ip_len);
    hlen = iph->get_hlen() << 2;

    /* header length sanity check */
    if(hlen < ip::IP4_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Bogus IP header length of %i bytes\n", hlen););

        codec_events::decoder_event(codec, DECODE_IPV4_INVALID_HEADER_LEN);
        return false;
    }

    if (ip_len > raw.len)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "IP Len field is %d bytes bigger than captured length.\n"
            "    (ip.len: %lu, cap.len: %lu)\n",
            ip_len - raw.len, ip_len, raw.len););

        codec_events::decoder_event(codec, DECODE_IPV4_DGRAM_GT_CAPLEN);
        return false;
    }
#if 0
    // There is no need to alert when (ip_len < len).
    // Libpcap will capture more bytes than are part of the IP payload.
    // These could be Ethernet trailers, ESP trailers, etc.
    // This code is left in, commented, to keep us from re-writing it later.
    else if (ip_len < len)
    {
        if (ScLogVerbose())
            ErrorMessage("IP Len field is %d bytes "
                    "smaller than captured length.\n"
                    "    (ip.len: %lu, cap.len: %lu)\n",
                    len - ip_len, ip_len, len);
    }
#endif

    if(ip_len < hlen)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "IP dgm len (%d bytes) < IP hdr "
            "len (%d bytes), packet discarded\n", ip_len, hlen););

        codec_events::decoder_event(codec, DECODE_IPV4_DGRAM_LT_IPHDR);
        return false;
    }

    // set the api now since this layer has been verified as valid
    snort.ip_api.set(iph);

    /*
     * IP Header tests: Land attack, and Loop back test
     */
    IP4AddrTests(iph, codec);

    if (ScIpChecksums())
    {
        /* routers drop packets with bad IP checksums, we don't really
         * need to check them (should make this a command line/config
         * option
         */
        int16_t csum = checksum::ip_cksum((uint16_t *)iph, hlen);

        if(csum)
        {
            snort.decode_flags |= DECODE_ERR_CKSUM_IP;

            // TBD only set policy csum drop if policy inline
            // and delete this inline mode check
            if( ScInlineMode() && ScIpChecksumDrops() )
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "Dropping bad packet (IP checksum)\n"););
                Active_DropPacket();
            }
        }
    }

    /* test for IP options */
    codec.codec_flags &= ~(CODEC_IPOPT_FLAGS);
    uint8_t ip_opt_len = (uint8_t)(hlen - ip::IP4_HEADER_LEN);

    if(ip_opt_len > 0)
        DecodeIPOptions((raw.data + ip::IP4_HEADER_LEN), ip_opt_len, codec);

    /* set the remaining packet length */
    const_cast<uint32_t&>(raw.len) = ip_len;
    ip_len -= hlen;

    /* check for fragmented packets */
    uint16_t frag_off = ntohs(iph->get_off());

    /*
     * get the values of the reserved, more
     * fragments and don't fragment flags
     */

#if 0
     // Reserved bit currently unused
    if (frag_off & 0x8000)
        data.decode_flags |= DECODE_RF;
#endif

    if (frag_off & 0x4000)
        codec.codec_flags |= CODEC_DF;

    if (frag_off & 0x2000)
        snort.decode_flags |= DECODE_MF;

    /* mask off the high bits in the fragment offset field */
    frag_off &= 0x1FFF;

    if ((codec.codec_flags & CODEC_DF) && frag_off )
        codec_events::decoder_event(codec, DECODE_IP4_DF_OFFSET);

    if ( frag_off + ip_len > IP_MAXPACKET )
        codec_events::decoder_event(codec, DECODE_IP4_LEN_OFFSET);

    if(frag_off || (snort.decode_flags & DECODE_MF))
    {
        if ( !ip_len)
        {
            codec_events::decoder_event(codec, DECODE_ZERO_LENGTH_FRAG);
            snort.decode_flags &= ~DECODE_FRAG;
        }
        else
        {
            /* set the packet fragment flag */
            snort.decode_flags |= DECODE_FRAG;
        }
    }
    else
    {
        snort.decode_flags &= ~DECODE_FRAG;
    }

    if( (snort.decode_flags & DECODE_MF) && (codec.codec_flags & CODEC_DF))
        codec_events::decoder_event(codec, DECODE_BAD_FRAGBITS);


    snort.set_pkt_type(PktType::IP);
    codec.proto_bits |= PROTO_BIT__IP;
    IPMiscTests(iph, codec, ip::IP4_HEADER_LEN + ip_opt_len);
    codec.lyr_len = hlen - codec.invalid_bytes;


    /* if this packet isn't a fragment
     * or if it is, its a UDP packet and offset is 0 */
    if(!(snort.decode_flags & DECODE_FRAG) ||
        ((frag_off == 0) &&
         (iph->get_proto() == IPPROTO_UDP)))
    {
        if (iph->get_proto() >= MIN_UNASSIGNED_IP_PROTO)
            codec_events::decoder_event(codec, DECODE_IP_UNASSIGNED_PROTO);
        else
            codec.next_prot_id = iph->get_proto();
    }

    // FIXIT-M J  tunnel-byppas is NOT checked!!

    return true;
}

//------------------------------------------------------------------
// decode.c::IP4 misc
//--------------------------------------------------------------------


static inline void IP4AddrTests(const IP4Hdr* iph, const CodecData& codec)
{
    uint8_t msb_src, msb_dst;

    // check all 32 bits ...
    if( iph->ip_src == iph->ip_dst )
    {
        codec_events::decoder_event(codec, DECODE_BAD_TRAFFIC_SAME_SRCDST);
    }

    // check all 32 bits ...
    if (iph->is_src_broadcast())
        codec_events::decoder_event(codec, DECODE_IP4_SRC_BROADCAST);

    if (iph->is_dst_broadcast())
        codec_events::decoder_event(codec, DECODE_IP4_DST_BROADCAST);

    /* Loopback traffic  - don't use htonl for speed reasons -
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    msb_src = (iph.ip_src >> 24);
    msb_dst = (iph.ip_dst >> 24);
#else
    msb_src = (uint8_t)(iph->ip_src & 0xff);
    msb_dst = (uint8_t)(iph->ip_dst & 0xff);
#endif
    // check the msb ...
    if ( (msb_src == ip::IP4_LOOPBACK) || (msb_dst == ip::IP4_LOOPBACK) )
    {
        codec_events::decoder_event(codec, DECODE_BAD_TRAFFIC_LOOPBACK);
    }
    // check the msb ...
    if ( msb_src == ip::IP4_THIS_NET )
        codec_events::decoder_event(codec, DECODE_IP4_SRC_THIS_NET);

    if ( msb_dst == ip::IP4_THIS_NET )
        codec_events::decoder_event(codec, DECODE_IP4_DST_THIS_NET);

    // check the 'msn' (most significant nibble) ...
    msb_src >>= 4;
    msb_dst >>= 4;

    if ( msb_src == ip::IP4_MULTICAST )
        codec_events::decoder_event(codec, DECODE_IP4_SRC_MULTICAST);

    if ( msb_src == ip::IP4_RESERVED )
        codec_events::decoder_event(codec, DECODE_IP4_SRC_RESERVED);

    if ( msb_dst == ip::IP4_RESERVED )
        codec_events::decoder_event(codec, DECODE_IP4_DST_RESERVED);
}


/* IPv4-layer decoder rules */
static inline void IPMiscTests(const IP4Hdr* const ip4h, const CodecData& codec, uint16_t len)
{

    /* Yes, it's an ICMP-related vuln in IP options. */
    uint8_t length, pointer;


    /* Alert on IP packets with either 0x07 (Record Route) or 0x44 (Timestamp)
       options that are specially crafted. */
    ip::IpOptionIterator iter(ip4h, (uint8_t)(len - ip::IP4_HEADER_LEN));
    for (const ip::IpOptions& opt : iter)
    {
        if (opt.code == ip::IPOptionCodes::RR)
        {
            length = opt.len;
            if (length < 3)
                continue;

            pointer = opt.data[0];

            /* If the pointer goes past the end of the data, then the data
               is full. That's okay. */
            if (pointer >= length)
                continue;
            /* If the remaining space in the option isn't a multiple of 4
               bytes, alert. */
            if (((length + 1) - pointer) % 4)
                codec_events::decoder_event(codec, DECODE_ICMP_DOS_ATTEMPT);
        }
        else if (opt.code == ip::IPOptionCodes::TS)
        {
            length = opt.get_len();
            if (length < 2)
                continue;

            pointer = opt.data[0];

            /* If the pointer goes past the end of the data, then the data
               is full. That's okay. */
            if (pointer >= length)
                continue;
            /* If the remaining space in the option isn't a multiple of 4
               bytes, alert. */
            if (((length + 1) - pointer) % 4)
                codec_events::decoder_event(codec, DECODE_ICMP_DOS_ATTEMPT);
            /* If there is a timestamp + address, we need a multiple of 8
               bytes instead. */
            if ((opt.data[1] & 0x01) && /* address flag */
               (((length + 1) - pointer) % 8))
                codec_events::decoder_event(codec, DECODE_ICMP_DOS_ATTEMPT);
        }
    }
}


/*
 * Function: DecodeIPOptions(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Once again, a fairly self-explainatory name
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
static void DecodeIPOptions(const uint8_t *start, uint8_t& o_len, CodecData& codec)
{
    uint32_t tot_len = 0;
    int code = 0;  /* negative error codes are returned from bad options */

    const ip::IpOptions* option = reinterpret_cast<const ip::IpOptions*>(start);

    while(tot_len < o_len)
    {
        switch(option->code)
        {
            case ip::IPOptionCodes::EOL:
                /* if we hit an EOL, we're done */
                tot_len++;
                codec.invalid_bytes = o_len - tot_len;
                o_len = tot_len;
                return;
                // fall through

            case ip::IPOptionCodes::NOP:
                tot_len++;
                break;

            case ip::IPOptionCodes::RTRALT:
                codec.codec_flags |= CODEC_IPOPT_RTRALT_SEEN;
                goto default_case;

            case ip::IPOptionCodes::RR:
                codec.codec_flags |= CODEC_IPOPT_RR_SEEN;
                // fall through

default_case:
            default:

                if((tot_len + 1) >= o_len)
                    code = tcp::OPT_TRUNC;

                /* RFC sez that we MUST have atleast this much data */
                else if (option->len < 2)
                    code = tcp::OPT_BADLEN;

                else if (tot_len + option->get_len() > o_len)
                    /* not enough data to read in a perfect world */
                    code = tcp::OPT_TRUNC;

                else if (option->len == 3)
                    /* for IGMP alert */
                    codec.codec_flags |= CODEC_IPOPT_LEN_THREE;


                if(code < 0)
                {
                    /* Yes, we use TCP_OPT_* for the IP option decoder. */
                    if(code == tcp::OPT_BADLEN)
                        codec_events::decoder_event(codec, DECODE_IPV4OPT_BADLEN);
                    else if(code == tcp::OPT_TRUNC)
                        codec_events::decoder_event(codec, DECODE_IPV4OPT_TRUNCATED);

                    codec.invalid_bytes = o_len - tot_len;
                    o_len = tot_len;
                    return;
                }

                tot_len += option->len;
        }


        option = &(option->next());
    }
}


/******************************************************************
 *********************  L O G G E R  ******************************
*******************************************************************/

struct ip4_addr
{
    union
    {
        uint32_t addr32;
        uint8_t addr8[4];
    };
};

void Ipv4Codec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const Packet* const p)
{
    const IP4Hdr* const ip4h = reinterpret_cast<const IP4Hdr*>(raw_pkt);

    // FIXIT-H  -->  This does NOT obfuscate correctly
    if (ScObfuscate())
    {
        TextLog_Print(text_log, "xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx");
    }
    else
    {
        ip4_addr src, dst;
        src.addr32 = ip4h->get_src();
        dst.addr32 = ip4h->get_dst();

        TextLog_Print(text_log, "%d.%d.%d.%d -> %d.%d.%d.%d",
            (int)src.addr8[0], (int)src.addr8[1],
            (int)src.addr8[2], (int)src.addr8[3],
            (int)dst.addr8[0], (int)dst.addr8[1],
            (int)dst.addr8[2], (int)dst.addr8[3]);
    }

    TextLog_NewLine(text_log);
    TextLog_Putc(text_log, '\t');


    const uint16_t hlen = ip4h->get_hlen() << 2;
    const uint16_t len = ntohs(ip4h->get_len());
    const uint16_t frag_off = ntohs(ip4h->get_off());

    TextLog_Print(text_log, "Next:0x%02X TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u",
            ip4h->get_proto(), ip4h->get_ttl(), ip4h->get_tos(),
            ip4h->get_id(), hlen, len);


    /* print the reserved bit if it's set */
    if(frag_off & 0x8000)
        TextLog_Puts(text_log, " RB");

    /* printf more frags/don't frag bits */
    if(frag_off & 0x4000)
        TextLog_Puts(text_log, " DF");

    if(frag_off & 0x2000)
        TextLog_Puts(text_log, " MF");

    /* print IP options */
    if (ip4h->has_options())
    {
        TextLog_Putc(text_log, '\t');
        TextLog_NewLine(text_log);
        LogIpOptions(text_log, ip4h, p);
    }


    if( p->ptrs.decode_flags & DECODE_FRAG)
    {
        TextLog_NewLine(text_log);
        TextLog_Putc(text_log, '\t');
        TextLog_Print(text_log, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
                (frag_off & 0x1FFF), (len - hlen));
    }
}

/******************************************************************
 ******************** E N C O D E R  ******************************
*******************************************************************/

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
        rand_shuffle(s_rand, &s_id_pool[0], sizeof(s_id_pool), 1);
#endif
    return id;
}

/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/
bool Ipv4Codec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
                        EncState& enc, Buffer& buf)
{
    if (!buf.allocate(sizeof(IP4Hdr)))
        return false;


    const ip::IP4Hdr* const ip4h_in = reinterpret_cast<const IP4Hdr*>(raw_in);
    ip::IP4Hdr* const ip4h_out = reinterpret_cast<IP4Hdr*>(buf.base);

    /* IPv4 encoded header is hardcoded 20 bytes */
    ip4h_out->ip_verhl = 0x45;
    ip4h_out->ip_off = 0;
    ip4h_out->ip_id = IpId_Next();
    ip4h_out->ip_tos = ip4h_in->ip_tos;
    ip4h_out->ip_proto = ip4h_in->ip_proto;
    ip4h_out->ip_len = htons((uint16_t)buf.size());
    ip4h_out->ip_csum = 0;

    if ( forward(enc.flags) )
    {
        ip4h_out->ip_src = ip4h_in->ip_src;
        ip4h_out->ip_dst = ip4h_in->ip_dst;
        ip4h_out->ip_ttl = enc.get_ttl(ip4h_in->ip_ttl);
    }
    else
    {
        ip4h_out->ip_src = ip4h_in->ip_dst;
        ip4h_out->ip_dst = ip4h_in->ip_src;
        ip4h_out->ip_ttl = enc.get_ttl(ip4h_in->ip_ttl);
    }

    if ( enc.next_proto_set() )
        ip4h_out->ip_proto = enc.next_proto;

    /* IPv4 encoded header is hardcoded 20 bytes, we save some
     * cycles and use the literal header size for checksum */
    ip4h_out->ip_csum = checksum::ip_cksum((uint16_t *)ip4h_out, ip::IP4_HEADER_LEN);

    enc.next_proto = IPPROTO_ID_IPIP;
    enc.next_ethertype = ETHERTYPE_IPV4;
    return true;
}


bool Ipv4Codec::update(Packet* p, Layer* lyr, uint32_t* len)
{
    IP4Hdr* h = (IP4Hdr*)(lyr->start);
    int i = lyr - p->layers;
    uint16_t hlen = h->get_hlen() << 2;

    *len += hlen;

    if ( i + 1 == p->num_layers )
        *len += p->dsize;


    h->set_ip_len(htons((uint16_t)*len));


    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) )
    {
        h->ip_csum = 0;
        h->ip_csum = checksum::ip_cksum((uint16_t *)h, hlen);
    }

    return true;
}

void Ipv4Codec::format(EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    // TBD handle nested ip layers
    IP4Hdr* ch = (IP4Hdr*)lyr->start;

    if ( reverse(f) )
    {
        int i = lyr - c->layers;
        IP4Hdr* ph = (IP4Hdr*)p->layers[i].start;

        ch->ip_src = ph->ip_dst;
        ch->ip_dst = ph->ip_src;
    }
    if ( f & ENC_FLAG_DEF )
    {
        lyr->length = ip::IP4_HEADER_LEN;
        ch->set_ip_len(htons(ip::IP4_HEADER_LEN));
        ch->set_hlen(ip::IP4_HEADER_LEN >> 2);

#if 0
        // FIXIT-L - J why did Snort check for this?
        int i = lyr - c->layers;
        if ( i + 1 == p->num_layers )
        {
            lyr->length = ip::IP4_HEADER_LEN;
            ch->set_ip_len(htons(ip::IP4_HEADER_LEN));
            ch->set_hlen(ip::IP4_HEADER_LEN >> 2);
        }
#endif
    }

    c->ptrs.ip_api.set(ch);
    c->ptrs.set_pkt_type(PktType::IP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Ipv4Module; }

static void mod_dtor(Module* m)
{ delete m; }

//-------------------------------------------------------------------------
// ip id considerations:
//
// we use dnet's rand services to generate a vector of random 16-bit values and
// iterate over the vector as IDs are assigned.  when we wrap to the beginning,
// the vector is randomly reordered.
//-------------------------------------------------------------------------
static void ipv4_codec_ginit()
{
#ifndef VALGRIND_TESTING
    if ( s_rand ) rand_close(s_rand);

    // rand_open() can yield valgrind errors because the
    // starting seed may come from "random stack contents"
    // (see man 3 dnet)
    s_rand = rand_open();

    if ( !s_rand )
        FatalError("rand_open() failed.\n");

    rand_get(s_rand, &s_id_pool[0], sizeof(s_id_pool));
#endif
}


static void ipv4_codec_gterm()
{
    if ( s_rand ) rand_close(s_rand);
    s_rand = NULL;
}


static Codec *ctor(Module*)
{ return new Ipv4Codec; }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi ipv4_api =
{
    { 
        PT_CODEC,
        CD_IPV4_NAME,
        CD_IPV4_HELP,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    ipv4_codec_ginit, // pinit
    ipv4_codec_gterm, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};

#if 0
#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ipv4_api.base,
    nullptr
};
#else
const BaseApi* cd_ipv4 = &ipv4_api.base;
#endif
#endif


// Currently needs to be static
const BaseApi* cd_ipv4 = &ipv4_api.base;
