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

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "snort.h"
#include "generators.h"
#include "fpdetect.h"


#include "protocols/tcp.h"
#include "protocols/ipv4.h"

#include "utils/stats.h"
#include "packet_io/active.h"
#include "codecs/decode_module.h"
#include "events/codec_events.h"

namespace{

class Ipv4Codec : public Codec
{
public:
    Ipv4Codec() : Codec("ipv4"){};
    ~Ipv4Codec(){};

    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_packet, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    // used in random classes throughout Snort++

    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_IP4; };

private:



    
};


uint16_t const IP_ID_COUNT = 8192;
THREAD_LOCAL rand_t* s_rand = 0;

#if 0
THREAD_LOCAL uint16_t s_id_index = 0;
#endif

// this should be changed to type array
THREAD_LOCAL uint16_t s_id_pool[IP_ID_COUNT] = {};

}  // namespace


static inline void CheckPGMVuln(Packet *);
static inline void CheckIGMPVuln(Packet *);
static inline int pgm_nak_detect (uint8_t *, uint16_t );
static inline void IP4AddrTests (Packet* );
static inline void IPMiscTests(Packet *);
static inline unsigned short in_chksum_ip( unsigned short *, int);

static void DecodeIPOptions(const uint8_t *start, uint32_t o_len, Packet *p);


void Ipv4Codec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ipv4::ethertype_ip());
    v.push_back(ipv4::prot_id());
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
bool Ipv4Codec::decode(const uint8_t *raw_packet, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    uint32_t ip_len; /* length from the start of the ip hdr to the pkt end */
    uint16_t hlen;  /* ip header length */

//    dc.ip++;

//    if (p->greh != NULL)
//        dc.gre_ip++;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    /* do a little validation */
    if(len < ipv4::hdr_len())
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated IP4 header (%d bytes).\n", len););

        if ((p->packet_flags & PKT_UNSURE_ENCAP) == 0)
            codec_events::decoder_event(p, DECODE_IP4_HDR_TRUNC);

        p->iph = NULL;
        p->family = NO_IP;

//        dc.discards++;
//        dc.ipdisc++;
        return false;
    }

    if (p->family != NO_IP)
    {
        if (p->encapsulated)
        {
            codec_events::decoder_alert_encapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION,
                raw_packet, len);

            return false;
        }
        else
        {
            p->encapsulated = 1;
            p->outer_iph = p->iph;
            p->outer_ip_data = p->ip_data;
            p->outer_ip_dsize = p->ip_dsize;
        }
    }

    /* lay the IP struct over the raw data */
    p->inner_iph = p->iph = reinterpret_cast<IPHdr*>(const_cast<uint8_t *>(raw_packet));
//    p->inner_iph = p->iph = reinterpret_cast<ipv4::IP4Hdr*>(const_cast<uint8_t *>(raw_packet));

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if(IP_VER((IPHdr*)raw_packet) != 4)
    {
        if ((p->packet_flags & PKT_UNSURE_ENCAP) == 0)
            codec_events::decoder_event(p, DECODE_NOT_IPV4_DGRAM);

        p->iph = NULL;
        p->family = NO_IP;

//        dc.discards++;
//        dc.ipdisc++;
        return false;
    }

    sfiph_build(p, p->iph, AF_INET);

    /* get the IP datagram length */
    ip_len = ntohs(p->iph->ip_len);

    /* get the IP header length */
    hlen = ipv4::get_pkt_hdr_len(p->iph) << 2;

    /* header length sanity check */
    if(hlen < ipv4::hdr_len())
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Bogus IP header length of %i bytes\n", hlen););

        codec_events::decoder_event(p, DECODE_IPV4_INVALID_HEADER_LEN);

        p->iph = NULL;
        p->family = NO_IP;

//        dc.discards++;
//        dc.ipdisc++;
        return false;
    }

    if (ip_len > len)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "IP Len field is %d bytes bigger than captured length.\n"
            "    (ip.len: %lu, cap.len: %lu)\n",
            ip_len - len, ip_len, len););

        codec_events::decoder_event(p, DECODE_IPV4_DGRAM_GT_CAPLEN);

        p->iph = NULL;
        p->family = NO_IP;

//        dc.discards++;
//        dc.ipdisc++;
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

        p->iph = NULL;
        p->family = NO_IP;

//        dc.discards++;
//        dc.ipdisc++;
        return false;
    }

    /*
     * IP Header tests: Land attack, and Loop back test
     */
    IP4AddrTests(p);

    if (ScIpChecksums())
    {
        /* routers drop packets with bad IP checksums, we don't really
         * need to check them (should make this a command line/config
         * option
         */
        int16_t csum = in_chksum_ip((u_short *)p->iph, hlen);

        if(csum)
        {
            p->error_flags |= PKT_ERR_CKSUM_IP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad IP checksum\n"););

            codec_events::exec_ip_chksm_drop(p);
//            dc.invalid_checksums++;
        }
#ifdef DEBUG_MSGS
        else
        {
            DebugMessage(DEBUG_DECODE, "IP Checksum: OK\n");
        }
#endif /* DEBUG */
    }

    /* test for IP options */
    p->ip_options_len = (uint16_t)(hlen - ipv4::hdr_len());

    if(p->ip_options_len > 0)
    {
        p->ip_options_data = raw_packet + ipv4::hdr_len();
        DecodeIPOptions((raw_packet + ipv4::hdr_len()), p->ip_options_len, p);
    }
    else
    {
        /* If delivery header for GRE encapsulated packet is IP and it
         * had options, the packet's ip options will be refering to this
         * outer IP's options
         * Zero these options so they aren't associated with this inner IP
         * since p->iph will be pointing to this inner IP
         */
        if (p->encapsulated)
        {
            p->ip_options_data = NULL;
            p->ip_options_len = 0;
        }
        p->ip_option_count = 0;
    }

    /* set the real IP length for logging */
    p->actual_ip_len = (uint16_t) ip_len;

    /* set the remaining packet length */
    ip_len -= hlen;

    /* check for fragmented packets */
    p->frag_offset = ntohs(p->iph->ip_off);

    /*
     * get the values of the reserved, more
     * fragments and don't fragment flags
     */
    p->rf = (uint8_t)((p->frag_offset & 0x8000) >> 15);
    p->df = (uint8_t)((p->frag_offset & 0x4000) >> 14);
    p->mf = (uint8_t)((p->frag_offset & 0x2000) >> 13);

    /* mask off the high bits in the fragment offset field */
    p->frag_offset &= 0x1FFF;

    if ( p->df && p->frag_offset )
        codec_events::decoder_event(p, DECODE_IP4_DF_OFFSET);

    if ( p->frag_offset + p->actual_ip_len > IP_MAXPACKET )
        codec_events::decoder_event(p, DECODE_IP4_LEN_OFFSET);

    if(p->frag_offset || p->mf)
    {
        if ( !ip_len)
        {
            codec_events::decoder_event(p, DECODE_ZERO_LENGTH_FRAG);
            p->frag_flag = 0;
        }
        else
        {
            /* set the packet fragment flag */
            p->frag_flag = 1;
            p->ip_frag_start = raw_packet + hlen;
            p->ip_frag_len = (uint16_t)ip_len;
//            dc.frags++;
        }
    }
    else
    {
        p->frag_flag = 0;
    }

    if( p->mf && p->df )
    {
        codec_events::decoder_event(p, DECODE_BAD_FRAGBITS);
    }

    /* Set some convienience pointers */
    p->ip_data = raw_packet + hlen;
    p->ip_dsize = (u_short) ip_len;

    /* See if there are any ip_proto only rules that match */
    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p);

    p->proto_bits |= PROTO_BIT__IP;

    IPMiscTests(p);
    lyr_len = hlen;

    /* if this packet isn't a fragment
     * or if it is, its a UDP packet and offset is 0 */
    if(!(p->frag_flag) ||
            (p->frag_flag && (p->frag_offset == 0) &&
            (p->iph->ip_proto == IPPROTO_UDP)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP header length: %lu\n",
                    (unsigned long)hlen););

        next_prot_id = p->iph->ip_proto;
    }
    else
    {
        /* set the payload pointer and payload size */
        p->data = raw_packet + hlen;
        p->dsize = (u_short) ip_len;
    }

    return true;
}


/* Function: DecodeIPv4Proto
 *
 * Gernalized IPv4 next protocol decoder dispatching.
 *
 * Arguments: proto => IPPROTO value of the next protocol
 *            pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the packet decode struct
 *
 */
inline void DecodeIPv4Proto(const uint8_t proto,
    const uint8_t *pkt, const uint32_t len, Packet *p)
{
    switch(proto)
    {


        case IPPROTO_IPV6:
//            dc.ip4ip6++;
//            if ( ScTunnelBypassEnabled(TUNNEL_6IN4) )
//                Active_SetTunnelBypass();
            return;

#if 0

#endif
        case IPPROTO_IP_MOBILITY:
        case IPPROTO_SUN_ND:
        case IPPROTO_PIM:
            codec_events::decoder_event(p, DECODE_IP_BAD_PROTO);
            p->data = pkt;
            p->dsize = (uint16_t)len;
            return;

        case IPPROTO_PGM:
            p->data = pkt;
            p->dsize = (uint16_t)len;

                CheckPGMVuln(p);
            return;

        case IPPROTO_IGMP:
            p->data = pkt;
            p->dsize = (uint16_t)len;
            CheckIGMPVuln(p);
            return;

        default:
            if (GET_IPH_PROTO(p) >= MIN_UNASSIGNED_IP_PROTO)
                codec_events::decoder_event(p, DECODE_IP_UNASSIGNED_PROTO);

            p->data = pkt;
            p->dsize = (uint16_t)len;
            return;
    }
}

static inline void CheckPGMVuln(Packet *p)
{
    if ( pgm_nak_detect((uint8_t *)p->data, p->dsize) == PGM_NAK_VULN )
        codec_events::decoder_event(p, DECODE_PGM_NAK_OVERFLOW);
}


//--------------------------------------------------------------------
//  IP4 vulnerabilities
//--------------------------------------------------------------------

/* This PGM NAK function started off as an SO rule, sid 8351. */
static inline int pgm_nak_detect (uint8_t *data, uint16_t length) {
    uint16_t data_left;
    uint16_t  checksum;
    PGM_HEADER *header;

    if (NULL == data) {
        return PGM_NAK_ERR;
    }

    /* request must be bigger than 44 bytes to cause vuln */
    if (length <= sizeof(PGM_HEADER)) {
        return PGM_NAK_ERR;
    }

    header = (PGM_HEADER *) data;

    if (8 != header->type) {
        return PGM_NAK_ERR;
    }

    if (2 != header->nak.opt.type) {
        return PGM_NAK_ERR;
    }


    /*
     * alert if the amount of data after the options is more than the length
     * specified.
     */


    data_left = length - 36;
    if (data_left > header->nak.opt.len) {

        /* checksum is expensive... do that only if the length is bad */
        if (header->checksum != 0) {
            checksum = in_chksum_ip((unsigned short*)data, (int)length);
            if (checksum != 0)
                return PGM_NAK_ERR;
        }

        return PGM_NAK_VULN;
    }

    return PGM_NAK_OK;
}


/* This function is a port of an old .so rule, sid 3:8092. */
static inline void CheckIGMPVuln(Packet *p)
{
    int i, alert = 0;

    if (p->dsize >= 1 && p->data[0] == 0x11)
    {
        if (p->ip_options_data != NULL) {
            if (p->ip_options_len >= 2) {
                if (*(p->ip_options_data) == 0 && *(p->ip_options_data+1) == 0)
                {
                    codec_events::decoder_event(p, DECODE_IGMP_OPTIONS_DOS);
                    return;
                }
            }
        }

        for(i=0; i< (int) p->ip_option_count; i++) {
            /* All IGMPv2 packets contain IP option code 148 (router alert).
               This vulnerability only applies to IGMPv3, so return early. */
            if (ipv4::is_opt_rtralt(p->ip_options[i].code)) {
                return; /* No alert. */
            }

            if (p->ip_options[i].len == 1) {
                alert++;
            }
        }

        if (alert > 0)
            codec_events::decoder_event(p, DECODE_IGMP_OPTIONS_DOS);
    }
}


//--------------------------------------------------------------------
// decode.c::IP4 misc
//--------------------------------------------------------------------


static inline void IP4AddrTests (Packet* p)
{
    uint8_t msb_src, msb_dst;

    // check all 32 bits ...
    if( p->iph->ip_src.s_addr == p->iph->ip_dst.s_addr )
    {
        codec_events::decoder_event(p, DECODE_BAD_TRAFFIC_SAME_SRCDST);

    }

    // check all 32 bits ...
    if ( ipv4::is_broadcast(p->iph->ip_src.s_addr)  )
        codec_events::decoder_event(p, DECODE_IP4_SRC_BROADCAST);

    if ( ipv4::is_broadcast(p->iph->ip_dst.s_addr)  )
        codec_events::decoder_event(p, DECODE_IP4_DST_BROADCAST);

    /* Loopback traffic  - don't use htonl for speed reasons -
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    msb_src = (p->iph->ip_src.s_addr >> 24);
    msb_dst = (p->iph->ip_dst.s_addr >> 24);
#else
    msb_src = (uint8_t)(p->iph->ip_src.s_addr & 0xff);
    msb_dst = (uint8_t)(p->iph->ip_dst.s_addr & 0xff);
#endif
    // check the msb ...
    if ( ipv4::is_loopback(msb_src) || ipv4::is_loopback(msb_dst) )
    {
        codec_events::decoder_event(p, DECODE_BAD_TRAFFIC_LOOPBACK);
    }
    // check the msb ...
    if ( ipv4::is_this_net(msb_src) )
        codec_events::decoder_event(p, DECODE_IP4_SRC_THIS_NET);

    if ( ipv4::is_this_net(msb_dst) )
        codec_events::decoder_event(p, DECODE_IP4_DST_THIS_NET);

    // check the 'msn' (most significant nibble) ...
    msb_src >>= 4;
    msb_dst >>= 4;

    if ( ipv4::is_multicast(msb_src) )
        codec_events::decoder_event(p, DECODE_IP4_SRC_MULTICAST);

    if ( ipv4::is_reserved(msb_src) )
        codec_events::decoder_event(p, DECODE_IP4_SRC_RESERVED);

    if ( ipv4::is_reserved(msb_dst))
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

        if (ipv4::is_opt_rr(p->ip_options[i].code))
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
        else if (ipv4::is_opt_ts(p->ip_options[i].code))
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



// TODO :: delete
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

        switch(static_cast<ipv4::IPOptionCodes>(*option_ptr))
        {
        case ipv4::IPOptionCodes::EOL:
            done = 1;
            // fall through
        
        case ipv4::IPOptionCodes::NOP:
            /* if we hit an EOL, we're done */

            p->ip_options[opt_count].len = 0;
            p->ip_options[opt_count].data = NULL;
            byte_skip = 1;
            break;
        default:
            /* handle all the dynamic features */
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

#if 0
static inline uint16_t IpId_Next ()
{
    uint16_t s_id_index = Get_s_id_index();
    uint16_t *s_id_pool = Get_s_id_pool();
    rand_t *s_rand = Get_s_rand();

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

/*
 * ENCODER
 */

EncStatus IP4_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int len;
    uint32_t start = out->end;
    uint16_t s_id_index = Get_s_id_index();
    uint16_t *s_id_pool = Get_s_id_pool();
    rand_t *s_rand = Get_s_rand();

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
        EncStatus err = encoders[next].fencode(enc, in, out);
        if ( EncStatus::ENC_OK != err ) return err;
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
    ho->ip_csum = in_chksum_ip((uint16_t *)ho, sizeof *ho);

    return EncStatus::ENC_OK;
}

EncStatus IP4_Update (Packet* p, Layer* lyr, uint32_t* len)
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
        h->ip_csum = in_chksum_ip((uint16_t *)h, GET_IP_HDR_LEN(h));
    }

    return EncStatus::ENC_OK;
}

void IP4_Format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
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

#endif

/*
 * CHECKSUM
 */


/*
*  checksum IP  - header=20+ bytes
*
*  w - short words of data
*  blen - byte length
*
*/
static inline unsigned short in_chksum_ip( unsigned short * w, int blen )
{
   unsigned int cksum;

   /* IP must be >= 20 bytes */
   cksum  = w[0];
   cksum += w[1];
   cksum += w[2];
   cksum += w[3];
   cksum += w[4];
   cksum += w[5];
   cksum += w[6];
   cksum += w[7];
   cksum += w[8];
   cksum += w[9];

   blen  -= 20;
   w     += 10;

   while( blen ) /* IP-hdr must be an integral number of 4 byte words */
   {
     cksum += w[0];
     cksum += w[1];
     w     += 2;
     blen  -= 4;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short) (~cksum);
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


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

    rand_get(s_rand, s_id_pool, sizeof(s_id_pool));
#endif
}


static void ipv4_codec_gterm()
{
    if ( s_rand ) rand_close(s_rand);
    s_rand = NULL;
}


static Codec *ctor()
{
    return new Ipv4Codec;
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const char* name = "ipv4";
static const CodecApi ipv4_api =
{
    { 
        PT_CODEC,
        name,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    ipv4_codec_ginit, // pinit
    ipv4_codec_gterm, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
};


const BaseApi* cd_ipv4 = &ipv4_api.base;
