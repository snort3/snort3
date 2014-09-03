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

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include <array>
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
#include "codecs/sf_protocols.h"
#include "protocols/ip.h"
#include "log/text_log.h"
#include "log/log_text.h"

namespace{

#define CD_IPV4_NAME "ipv4"
static const RuleMap ipv4_rules[] =
{
    { DECODE_NOT_IPV4_DGRAM, "(" CD_IPV4_NAME ") Not IPv4 datagram" },
    { DECODE_IPV4_INVALID_HEADER_LEN, "(" CD_IPV4_NAME ") hlen < IP_HEADER_LEN" },
    { DECODE_IPV4_DGRAM_LT_IPHDR, "(" CD_IPV4_NAME ") IP dgm len < IP Hdr len" },
    { DECODE_IPV4OPT_BADLEN, "(" CD_IPV4_NAME ") Ipv4 Options found with bad lengths" },
    { DECODE_IPV4OPT_TRUNCATED, "(" CD_IPV4_NAME ") Truncated Ipv4 Options" },
    { DECODE_IPV4_DGRAM_GT_CAPLEN, "(" CD_IPV4_NAME ") IP dgm len > captured len" },
    { DECODE_ZERO_TTL, "(" CD_IPV4_NAME ") IPV4 packet with zero TTL" },
    { DECODE_BAD_FRAGBITS, "(" CD_IPV4_NAME ") IPV4 packet with bad frag bits (Both MF and DF set)" },
    { DECODE_IP4_LEN_OFFSET, "(" CD_IPV4_NAME ") IPV4 packet frag offset + length exceed maximum" },
    { DECODE_IP4_SRC_THIS_NET, "(" CD_IPV4_NAME ") IPV4 packet from 'current net' source address" },
    { DECODE_IP4_DST_THIS_NET, "(" CD_IPV4_NAME ") IPV4 packet to 'current net' dest address" },
    { DECODE_IP4_SRC_MULTICAST, "(" CD_IPV4_NAME ") IPV4 packet from multicast source address" },
    { DECODE_IP4_SRC_RESERVED, "(" CD_IPV4_NAME ") IPV4 packet from reserved source address" },
    { DECODE_IP4_DST_RESERVED, "(" CD_IPV4_NAME ") IPV4 packet to reserved dest address" },
    { DECODE_IP4_SRC_BROADCAST, "(" CD_IPV4_NAME ") IPV4 packet from broadcast source address" },
    { DECODE_IP4_DST_BROADCAST, "(" CD_IPV4_NAME ") IPV4 packet to broadcast dest address" },
    { DECODE_IP4_MIN_TTL, "(" CD_IPV4_NAME ") IPV4 packet below TTL limit" },
    { DECODE_IP4_DF_OFFSET, "(" CD_IPV4_NAME ") IPV4 packet both DF and offset set" },
    { DECODE_IP_RESERVED_FRAG_BIT, "(" CD_IPV4_NAME ") BAD-TRAFFIC IP reserved bit set" },
    { DECODE_IP_UNASSIGNED_PROTO, "(" CD_IPV4_NAME ") BAD-TRAFFIC Unassigned/Reserved IP protocol" },
    { DECODE_IP_BAD_PROTO, "(" CD_IPV4_NAME ") BAD-TRAFFIC Bad IP protocol" },
    { DECODE_IP_OPTION_SET, "(" CD_IPV4_NAME ") MISC IP option set" },
    { DECODE_IP_MULTIPLE_ENCAPSULATION, "(" CD_IPV4_NAME ") Two or more IP (v4 and/or v6) encapsulation layers present" },
    { DECODE_ZERO_LENGTH_FRAG, "(" CD_IPV4_NAME ") fragment with zero length" },
    { DECODE_IP4_HDR_TRUNC, "(" CD_IPV4_NAME ") truncated IP4 header" },
    { DECODE_BAD_TRAFFIC_LOOPBACK, "(" CD_IPV4_NAME ") Bad Traffic Loopback IP" },
    { DECODE_BAD_TRAFFIC_SAME_SRCDST, "(" CD_IPV4_NAME ") Bad Traffic Same Src/Dst IP" },
    { 0, nullptr }
};

class Ipv4Module : public DecodeModule
{
public:
    Ipv4Module() : DecodeModule(CD_IPV4_NAME) {}

    const RuleMap* get_rules() const
    { return ipv4_rules; }
};



class Ipv4Codec : public Codec
{
public:
    Ipv4Codec() : Codec(CD_IPV4_NAME){};
    ~Ipv4Codec(){};

    virtual PROTO_ID get_proto_id() { return PROTO_IP4; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/,
        const Packet* const);
    virtual bool encode(EncState*, Buffer* out, const uint8_t* raw_in);
    virtual bool update(Packet*, Layer*, uint32_t* len);
    virtual void format(EncodeFlags, const Packet* p, Packet* c, Layer*);


private:
    static uint8_t RevTTL (const EncState* enc, uint8_t ttl);
    static uint8_t FwdTTL (const EncState* enc, uint8_t ttl);
    static uint8_t GetTTL (const EncState* enc);
};

/* Last updated 5/2/2014.
   Source: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml */
const uint16_t MIN_UNASSIGNED_IP_PROTO = 143;

const uint16_t IP_ID_COUNT = 8192;
static THREAD_LOCAL rand_t* s_rand = 0;
static THREAD_LOCAL uint16_t s_id_index = 0;
static THREAD_LOCAL std::array<uint16_t, IP_ID_COUNT> s_id_pool{{0}};

}  // namespace


static inline void IP4AddrTests (const IP4Hdr*, const Packet* p);
static inline void IPMiscTests(Packet *);
static void DecodeIPOptions(const uint8_t *start, uint32_t o_len, Packet *p);

static int OptLenValidate(const uint8_t *option_ptr,
                                 const uint8_t *end,
                                 const uint8_t *len_ptr,
                                 int expected_len,
                                 Options *tcpopt,
                                 uint8_t *byte_skip);

/*******************************************
 ************  PRIVATE FUNCTIONS ***********
 *******************************************/

uint8_t Ipv4Codec::GetTTL (const EncState* enc)
{
    char dir;
    uint8_t ttl;
    const bool outer = enc->p->ip_api.is_valid();

    if ( !enc->p->flow )
        return 0;

    if ( enc->p->packet_flags & PKT_FROM_CLIENT )
        dir = forward(enc->flags) ? SSN_DIR_CLIENT : SSN_DIR_SERVER;
    else
        dir = forward(enc->flags) ? SSN_DIR_SERVER : SSN_DIR_CLIENT;

    // outermost ip is considered to be outer here,
    // even if it is the only ip layer ...
    ttl = stream.get_session_ttl(enc->p->flow, dir, outer);

    // so if we don't get outer, we use inner
    if ( 0 == ttl && outer )
        ttl = stream.get_session_ttl(enc->p->flow, dir, false);

    return ttl;
}

uint8_t Ipv4Codec::FwdTTL (const EncState* enc, uint8_t ttl)
{
    uint8_t new_ttl = GetTTL(enc);
    if ( !new_ttl )
        new_ttl = ttl;
    return new_ttl;
}

uint8_t Ipv4Codec::RevTTL (const EncState* enc, uint8_t ttl)
{
    uint8_t new_ttl = GetTTL(enc);
    if ( !new_ttl )
        new_ttl = ( MAX_TTL - ttl );
    if ( new_ttl < MIN_TTL )
        new_ttl = MIN_TTL;
    return new_ttl;
}



void Ipv4Codec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_IPV4);
    v.push_back(IPPROTO_ID_IPIP);
}

//--------------------------------------------------------------------
// prot_ipv4.cc::IP4 decoder
//--------------------------------------------------------------------

/*
 * Function: DecodeIP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the packet decode struct
 *
 * Returns: void function
 */
bool Ipv4Codec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    uint32_t ip_len; /* length from the start of the ip hdr to the pkt end */
    uint16_t hlen;  /* ip header length */

    /* do a little validation */
    if(raw_len < ip::IP4_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated IP4 header (%d bytes).\n", raw_len););

        if ((p->decode_flags & DECODE__UNSURE_ENCAP) == 0)
            codec_events::decoder_event(p, DECODE_IP4_HDR_TRUNC);
        return false;
    }

    // comparable to snort
    if (p->encapsulations > 1)
        codec_events::decoder_event(p, DECODE_IP_MULTIPLE_ENCAPSULATION);

    /* lay the IP struct over the raw data */
    const IP4Hdr* const iph = reinterpret_cast<const IP4Hdr*>(raw_pkt);

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if (iph->get_ver() != 4)
    {
        if ((p->decode_flags & DECODE__UNSURE_ENCAP) == 0)
            codec_events::decoder_event(p, DECODE_NOT_IPV4_DGRAM);
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

        codec_events::decoder_event(p, DECODE_IPV4_INVALID_HEADER_LEN);
        return false;
    }

    if (ip_len > raw_len)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "IP Len field is %d bytes bigger than captured length.\n"
            "    (ip.len: %lu, cap.len: %lu)\n",
            ip_len - raw_len, ip_len, raw_len););

        codec_events::decoder_event(p, DECODE_IPV4_DGRAM_GT_CAPLEN);
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

        codec_events::decoder_event(p, DECODE_IPV4_DGRAM_LT_IPHDR);
        return false;
    }

    // set the api now since this layer has been verified as valid
    p->ip_api.set(iph);

    /*
     * IP Header tests: Land attack, and Loop back test
     */
    IP4AddrTests(iph, p);

    if (ScIpChecksums())
    {
        /* routers drop packets with bad IP checksums, we don't really
         * need to check them (should make this a command line/config
         * option
         */
        int16_t csum = checksum::ip_cksum((uint16_t *)iph, hlen);

        if(csum)
        {
            p->error_flags |= PKT_ERR_CKSUM_IP;

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
    uint16_t ip_opt_len = (uint16_t)(hlen - ip::IP4_HEADER_LEN);

    if(ip_opt_len > 0)
    {
        DecodeIPOptions((raw_pkt + ip::IP4_HEADER_LEN), ip_opt_len, p);
    }
    else
    {
        /* If delivery header for GRE encapsulated packet is IP and it
         * had options, the packet's ip options will be refering to this
         * outer IP's options
         * Zero these options so they aren't associated with this inner IP
         * since p->iph will be pointing to this inner IP
         */
        p->ip_option_count = 0;
    }

    /* set the remaining packet length */
    const_cast<uint32_t&>(raw_len) = ip_len;
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
        p->decode_flags |= DECODE__RF;
#endif

    if (frag_off & 0x4000)
        p->decode_flags |= DECODE__DF;

    if (frag_off & 0x2000)
        p->decode_flags |= DECODE__MF;

    /* mask off the high bits in the fragment offset field */
    frag_off &= 0x1FFF;

    if ((p->decode_flags & DECODE__DF) && frag_off )
        codec_events::decoder_event(p, DECODE_IP4_DF_OFFSET);

    if ( frag_off + ip_len > IP_MAXPACKET )
        codec_events::decoder_event(p, DECODE_IP4_LEN_OFFSET);

    if(frag_off || (p->decode_flags & DECODE__MF))
    {
        if ( !ip_len)
        {
            codec_events::decoder_event(p, DECODE_ZERO_LENGTH_FRAG);
            p->decode_flags &= ~DECODE__FRAG;
        }
        else
        {
            /* set the packet fragment flag */
            p->decode_flags |= DECODE__FRAG;
            p->ip_frag_start = raw_pkt + hlen;
            p->ip_frag_len = (uint16_t)ip_len;
        }
    }
    else
    {
        p->decode_flags &= ~DECODE__FRAG;
    }

    if( (p->decode_flags & DECODE__MF) && (p->decode_flags & DECODE__DF))
    {
        codec_events::decoder_event(p, DECODE_BAD_FRAGBITS);
    }

    p->frag_offset = frag_off;

    /* See if there are any ip_proto only rules that match */
    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p, iph->get_proto());

    p->proto_bits |= PROTO_BIT__IP;
    IPMiscTests(p);
    lyr_len = hlen;

    /* if this packet isn't a fragment
     * or if it is, its a UDP packet and offset is 0 */
    if(!(p->decode_flags & DECODE__FRAG) ||
            ((p->decode_flags & DECODE__FRAG) && (frag_off == 0) &&
            (iph->get_proto() == IPPROTO_UDP)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP header length: %lu\n",
                    (unsigned long)hlen););

        if (iph->get_proto() >= MIN_UNASSIGNED_IP_PROTO)
            codec_events::decoder_event(p, DECODE_IP_UNASSIGNED_PROTO);
        else
            next_prot_id = iph->get_proto();
    }

    return true;
}

//------------------------------------------------------------------
// decode.c::IP4 misc
//--------------------------------------------------------------------


static inline void IP4AddrTests(const IP4Hdr* iph, const Packet* p)
{
    uint8_t msb_src, msb_dst;

    // check all 32 bits ...
    if( iph->ip_src == iph->ip_dst )
    {
        codec_events::decoder_event(p, DECODE_BAD_TRAFFIC_SAME_SRCDST);
    }

    // check all 32 bits ...
    if (iph->is_src_broadcast())
        codec_events::decoder_event(p, DECODE_IP4_SRC_BROADCAST);

    if (iph->is_dst_broadcast())
        codec_events::decoder_event(p, DECODE_IP4_DST_BROADCAST);

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
        codec_events::decoder_event(p, DECODE_BAD_TRAFFIC_LOOPBACK);
    }
    // check the msb ...
    if ( msb_src == ip::IP4_THIS_NET )
        codec_events::decoder_event(p, DECODE_IP4_SRC_THIS_NET);

    if ( msb_dst == ip::IP4_THIS_NET )
        codec_events::decoder_event(p, DECODE_IP4_DST_THIS_NET);

    // check the 'msn' (most significant nibble) ...
    msb_src >>= 4;
    msb_dst >>= 4;

    if ( msb_src == ip::IP4_MULTICAST )
        codec_events::decoder_event(p, DECODE_IP4_SRC_MULTICAST);

    if ( msb_src == ip::IP4_RESERVED )
        codec_events::decoder_event(p, DECODE_IP4_SRC_RESERVED);

    if ( msb_dst == ip::IP4_RESERVED )
        codec_events::decoder_event(p, DECODE_IP4_DST_RESERVED);
}


/* IPv4-layer decoder rules */
static inline void IPMiscTests(Packet *p)
{

    /* Yes, it's an ICMP-related vuln in IP options. */
    uint8_t i, length, pointer;

    /* Alert on IP packets with either 0x07 (Record Route) or 0x44 (Timestamp)
       options that are specially crafted. */
    for (i = 0; i < p->ip_option_count; i++)
    {
        if (p->ip_options[i].data == NULL)
            continue;

        if (p->ip_options[i].is_opt_rr())
        {
            length = p->ip_options[i].len;
            if (length < 1)
                continue;

            pointer = p->ip_options[i].data[0];

            /* If the pointer goes past the end of the data, then the data
               is full. That's okay. */
            if (pointer >= length + 2)
                continue;
            /* If the remaining space in the option isn't a multiple of 4
               bytes, alert. */
            if (((length + 3) - pointer) % 4)
                codec_events::decoder_event(p, DECODE_ICMP_DOS_ATTEMPT);
        }
        else if (p->ip_options[i].is_opt_ts())
        {
            length = p->ip_options[i].len;
            if (length < 2)
                continue;

            pointer = p->ip_options[i].data[0];

            /* If the pointer goes past the end of the data, then the data
               is full. That's okay. */
            if (pointer >= length + 2)
                continue;
            /* If the remaining space in the option isn't a multiple of 4
               bytes, alert. */
            if (((length + 3) - pointer) % 4)
                codec_events::decoder_event(p, DECODE_ICMP_DOS_ATTEMPT);
            /* If there is a timestamp + address, we need a multiple of 8
               bytes instead. */
            if ((p->ip_options[i].data[1] & 0x01) && /* address flag */
               (((length + 3) - pointer) % 8))
                codec_events::decoder_event(p, DECODE_ICMP_DOS_ATTEMPT);
        }
    }
}



// TODO :: delete.  IN TCP
int OptLenValidate(const uint8_t *option_ptr,
                                 const uint8_t *end,
                                 const uint8_t *len_ptr,
                                 int expected_len,
                                 Options *tcpopt,
                                 uint8_t *byte_skip);

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
static void DecodeIPOptions(const uint8_t *start, uint32_t o_len, Packet *p)
{
    const uint8_t *option_ptr = start;
    u_char done = 0; /* have we reached IP_OPTEOL yet? */
    const uint8_t *end_ptr = start + o_len;
    uint8_t opt_count = 0; /* what option are we processing right now */
    uint8_t byte_skip;
    const uint8_t *len_ptr;
    int code = 0;  /* negative error codes are returned from bad options */


    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,  "Decoding %d bytes of IP options\n", o_len););


    while((option_ptr < end_ptr) && (opt_count < IP_OPTMAX) && (code >= 0))
    {
        p->ip_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }

        switch(static_cast<ip::IPOptionCodes>(*option_ptr))
        {
        case ip::IPOptionCodes::EOL:
            done = 1;
            // fall through
        
        case ip::IPOptionCodes::NOP:
            /* if we hit an EOL, we're done */

            p->ip_options[opt_count].len = 0;
            p->ip_options[opt_count].data = NULL;
            byte_skip = 1;
            break;
        default:
            /* FIXIT-L - J ip option validation should be updated.  3 of these fields are useless */
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                    reinterpret_cast<Options *>(&p->ip_options[opt_count]), &byte_skip);
        }

        if(code < 0)
        {
            /* Yes, we use TCP_OPT_* for the IP option decoder.
            */
            if(code == tcp::OPT_BADLEN)
            {
                codec_events::decoder_event(p, DECODE_IPV4OPT_BADLEN);
            }
            else if(code == tcp::OPT_TRUNC)
            {
                codec_events::decoder_event(p, DECODE_IPV4OPT_TRUNCATED);
            }
            return;
        }

        if(!done)
            opt_count++;

        option_ptr += byte_skip;
    }

    p->ip_option_count = opt_count;

    return;
}


static int OptLenValidate(const uint8_t *option_ptr,
                                 const uint8_t *end,
                                 const uint8_t *len_ptr,
                                 int expected_len,
                                 Options *tcpopt,
                                 uint8_t *byte_skip)
{
    *byte_skip = 0;

    if(len_ptr == NULL)
        return tcp::OPT_TRUNC;


    if(*len_ptr == 0 || expected_len == 0 || expected_len == 1)
    {
        return tcp::OPT_BADLEN;
    }
    else if(expected_len > 1)
    {
        /* not enough data to read in a perfect world */
        if((option_ptr + expected_len) > end)
            return tcp::OPT_TRUNC;

        if(*len_ptr != expected_len)
            return tcp::OPT_BADLEN;
    }
    else /* expected_len < 0 (i.e. variable length) */
    {
        /* RFC sez that we MUST have atleast this much data */
        if(*len_ptr < 2)
            return tcp::OPT_BADLEN;

        /* not enough data to read in a perfect world */
        if((option_ptr + *len_ptr) > end)
            return tcp::OPT_TRUNC;
    }

    tcpopt->len = *len_ptr - 2;

    if(*len_ptr == 2)
        tcpopt->data = NULL;
    else
        tcpopt->data = option_ptr + 2;

    *byte_skip = *len_ptr;

    return 0;
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
    if(p->ip_option_count > 0)
    {
        TextLog_Putc(text_log, '\t');
        TextLog_NewLine(text_log);
        LogIpOptions(text_log, p);
    }


    if( p->decode_flags & DECODE__FRAG)
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

bool Ipv4Codec::encode(EncState* enc, Buffer* out, const uint8_t* raw_in)
{
    IP4Hdr *ho;

    if (!update_buffer(out, sizeof(*ho)))
        return false;


    const IP4Hdr *hi = reinterpret_cast<const IP4Hdr*>(raw_in);
    ho = reinterpret_cast<IP4Hdr*>(out->base);

    /* IPv4 encoded header is hardcoded 20 bytes */
    ho->ip_verhl = 0x45;
    ho->ip_off = 0;
    ho->ip_id = IpId_Next();
    ho->ip_tos = hi->ip_tos;
    ho->ip_proto = hi->ip_proto;
    ho->ip_len = htons((uint16_t)out->end);
    ho->ip_csum = 0;

    if ( forward(enc->flags) )
    {
        ho->ip_src = hi->ip_src;
        ho->ip_dst = hi->ip_dst;
        ho->ip_ttl = FwdTTL(enc, hi->ip_ttl);
    }
    else
    {
        ho->ip_src = hi->ip_dst;
        ho->ip_dst = hi->ip_src;
        ho->ip_ttl = RevTTL(enc, hi->ip_ttl);
    }

    if ( enc->proto )
    {
        ho->ip_proto = enc->proto;
        enc->proto = 0;
    }


    /* IPv4 encoded header is hardcoded 20 bytes, we save some
     * cycles and use the literal header size for checksum */
    ho->ip_csum = checksum::ip_cksum((uint16_t *)ho, ip::IP4_HEADER_LEN);
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
        int i = lyr - c->layers;
        if ( i + 1 == p->num_layers )
        {
            lyr->length = ip::IP4_HEADER_LEN;
            ch->set_ip_len(htons(ip::IP4_HEADER_LEN));
            ch->set_hlen(ip::IP4_HEADER_LEN >> 2);
        }
    }

    c->ip_api.set(ch);
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
