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
// cd_icmp4.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "main/snort.h"
#include "protocols/icmp4.h"
#include "codecs/codec_events.h"
#include "codecs/ip/checksum.h"
#include "protocols/protocol_ids.h"
#include "protocols/packet.h"
#include "codecs/decode_module.h"
#include "codecs/sf_protocols.h"
#include "codecs/ip/ip_util.h"
#include "packet_io/active.h"
#include "log/text_log.h"

#define CD_ICMP4_NAME "icmp4"
#define CD_ICMP4_HELP "support for internet control message protocol v4"

namespace{

static const RuleMap icmp4_rules[] =
{
    { DECODE_ICMP_DGRAM_LT_ICMPHDR, "(" CD_ICMP4_NAME ") ICMP Header Truncated" },
    { DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR, "(" CD_ICMP4_NAME ") ICMP Timestamp Header Truncated" },
    { DECODE_ICMP_DGRAM_LT_ADDRHDR, "(" CD_ICMP4_NAME ") ICMP Address Header Truncated" },
    { DECODE_ICMP_ORIG_IP_TRUNCATED, "(" CD_ICMP4_NAME ") ICMP Original IP Header Truncated" },
    { DECODE_ICMP_ORIG_IP_VER_MISMATCH, "(" CD_ICMP4_NAME ") ICMP version and Original IP Header versions differ" },
    { DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP, "(" CD_ICMP4_NAME ") ICMP Original Datagram Length < Original IP Header Length" },
    { DECODE_ICMP_ORIG_PAYLOAD_LT_64, "(" CD_ICMP4_NAME ") ICMP Original IP Payload < 64 bits" },
    { DECODE_ICMP_ORIG_PAYLOAD_GT_576, "(" CD_ICMP4_NAME ") ICMP Origianl IP Payload > 576 bytes" },
    { DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET, "(" CD_ICMP4_NAME ") ICMP Original IP Fragmented and Offset Not 0" },
    { DECODE_ICMP4_DST_MULTICAST, "(" CD_ICMP4_NAME ") ICMP4 packet to multicast dest address" },
    { DECODE_ICMP4_DST_BROADCAST, "(" CD_ICMP4_NAME ") ICMP4 packet to broadcast dest address" },
    { DECODE_ICMP4_TYPE_OTHER, "(" CD_ICMP4_NAME ") ICMP4 type other" },
    { DECODE_ICMP_PING_NMAP, "(" CD_ICMP4_NAME ") ICMP PING NMAP" },
    { DECODE_ICMP_ICMPENUM, "(" CD_ICMP4_NAME ") ICMP icmpenum v1.1.1" },
    { DECODE_ICMP_REDIRECT_HOST, "(" CD_ICMP4_NAME ") ICMP redirect host" },
    { DECODE_ICMP_REDIRECT_NET, "(" CD_ICMP4_NAME ") ICMP redirect net" },
    { DECODE_ICMP_TRACEROUTE_IPOPTS, "(" CD_ICMP4_NAME ") ICMP traceroute ipopts" },
    { DECODE_ICMP_SOURCE_QUENCH, "(" CD_ICMP4_NAME ") ICMP Source Quench" },
    { DECODE_ICMP_BROADSCAN_SMURF_SCANNER, "(" CD_ICMP4_NAME ") Broadscan Smurf Scanner" },
    { DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED, "(" CD_ICMP4_NAME ") ICMP Destination Unreachable Communication Administratively Prohibited" },
    { DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED, "(" CD_ICMP4_NAME ") ICMP Destination Unreachable Communication with Destination Host is Administratively Prohibited" },
    { DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED, "(" CD_ICMP4_NAME ") ICMP Destination Unreachable Communication with Destination Network is Administratively Prohibited" },
    { DECODE_ICMP_PATH_MTU_DOS, "(" CD_ICMP4_NAME ") ICMP PATH MTU denial of service attempt" },
    { DECODE_ICMP_DOS_ATTEMPT, "(" CD_ICMP4_NAME ") BAD-TRAFFIC linux ICMP header dos attempt" },
    { DECODE_ICMP4_HDR_TRUNC, "(" CD_ICMP4_NAME ") truncated ICMP4 header" },
    { 0, nullptr }
};

class Icmp4Module : public DecodeModule
{
public:
    Icmp4Module() : DecodeModule(CD_ICMP4_NAME, CD_ICMP4_HELP) {}

    const RuleMap* get_rules() const
    { return icmp4_rules; }
};

class Icmp4Codec : public Codec{

public:
    Icmp4Codec() : Codec(CD_ICMP4_NAME){};
    ~Icmp4Codec() {};
    
    virtual PROTO_ID get_proto_id() { return PROTO_ICMP4; };
    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual bool decode(const uint8_t* raw_packet, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual bool encode(EncState*, Buffer* out, const uint8_t* raw_in);
    virtual bool update(Packet*, Layer*, uint32_t* len);
    virtual void format(EncodeFlags, const Packet* p, Packet* c, Layer*);
    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/,
                    const Packet* const);

private:
    void ICMP4AddrTests (Packet* );
    void ICMP4MiscTests (Packet *);

};

} // namespace

void Icmp4Codec::get_protocol_ids(std::vector<uint16_t> &v)
{ v.push_back(IPPROTO_ID_ICMPV4); }




//--------------------------------------------------------------------
// decode.c::ICMP
//--------------------------------------------------------------------

/*
 * Function: DecodeICMP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the decoded packet struct
 *
 * Returns: void function
 */
bool Icmp4Codec::decode(const uint8_t* raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t& next_prot_id)
{

    if(raw_len < icmp::ICMP_HEADER_LEN)
    {
        codec_events::decoder_event(p, DECODE_ICMP4_HDR_TRUNC);
        p->icmph = NULL;
        return false;
    }

    /* set the header ptr first */

    p->icmph = reinterpret_cast<const ICMPHdr *>(raw_pkt);

    switch (p->icmph->type)
    {
            // fall through ...
        case icmp::IcmpType::SOURCE_QUENCH:
        case icmp::IcmpType::DEST_UNREACH:
        case icmp::IcmpType::REDIRECT:
        case icmp::IcmpType::TIME_EXCEEDED:
        case icmp::IcmpType::PARAMETERPROB:
        case icmp::IcmpType::ECHOREPLY:
        case icmp::IcmpType::ECHO_4:
        case icmp::IcmpType::ROUTER_ADVERTISE:
        case icmp::IcmpType::ROUTER_SOLICIT:
        case icmp::IcmpType::INFO_REQUEST:
        case icmp::IcmpType::INFO_REPLY:
            if (raw_len < 8)
            {
                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                return false;
            }
            break;

        case icmp::IcmpType::TIMESTAMP:
        case icmp::IcmpType::TIMESTAMPREPLY:
            if (raw_len < 20)
            {
                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR);

                p->icmph = NULL;
                return false;
            }
            break;

        case icmp::IcmpType::ADDRESS:
        case icmp::IcmpType::ADDRESSREPLY:
            if (raw_len < 12)
            {
                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ADDRHDR);
                p->icmph = NULL;
                return false;
            }
            break;

        default:
            codec_events::decoder_event(p, DECODE_ICMP4_TYPE_OTHER);
            break;
    }


    if (ScIcmpChecksums())
    {
        uint16_t csum = checksum::cksum_add((uint16_t *)p->icmph, raw_len);

        if(csum)
        {
            p->error_flags |= PKT_ERR_CKSUM_ICMP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: BAD\n"););

            if( ScInlineMode() && ScIcmpChecksumDrops() )
                Active_DropPacket();
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: OK\n"););
        }
    }

    lyr_len =  icmp::ICMP_HEADER_LEN;

    switch(p->icmph->type)
    {
        case icmp::IcmpType::ECHO_4:
            ICMP4AddrTests(p);
        // fall through ...

        case icmp::IcmpType::ECHOREPLY:
            /* setup the pkt id and seq numbers */
            /* add the size of the echo ext to the data
             * ptr and subtract it from the data size */
            lyr_len += sizeof(ICMPHdr::icmp_hun.idseq);
            break;

        case icmp::IcmpType::DEST_UNREACH:
            if ((p->icmph->code == icmp::IcmpCode::FRAG_NEEDED)
                    && (ntohs(p->icmph->s_icmp_nextmtu) < 576))
            {
                codec_events::decoder_event(p, DECODE_ICMP_PATH_MTU_DOS);
            }

            /* Fall through */

        case icmp::IcmpType::SOURCE_QUENCH:
        case icmp::IcmpType::REDIRECT:
        case icmp::IcmpType::TIME_EXCEEDED:
        case icmp::IcmpType::PARAMETERPROB:
            /* account for extra 4 bytes in header */
            lyr_len += 4;
            next_prot_id = IP_EMBEDDED_IN_ICMP4;
            break;

        default:
            break;
    }


    /* Run a bunch of ICMP decoder rules */
    p->dsize = (u_short)(raw_len - lyr_len); // setting for use in ICMP4MiscTests
    ICMP4MiscTests(p);

    p->proto_bits |= PROTO_BIT__ICMP;
    p->proto_bits &= ~(PROTO_BIT__UDP | PROTO_BIT__TCP);
    return true;
}

void Icmp4Codec::ICMP4AddrTests(Packet* p)
{
    uint8_t msb_dst;

    uint32_t dst = p->ip_api.get_dst()->ip32[0];

    // check all 32 bits; all set so byte order is irrelevant ...
    if ( dst == ip::IP4_BROADCAST )
        codec_events::decoder_event(p, DECODE_ICMP4_DST_BROADCAST);

    /* - don't use htonl for speed reasons -
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    msb_dst = (uint8_t)(dst >> 24);
#else
    msb_dst = (uint8_t)(dst & 0xff);
#endif

    // check the 'msn' (most significant nibble) ...
    msb_dst >>= 4;

    if( msb_dst == ip::IP4_MULTICAST )
        codec_events::decoder_event(p, DECODE_ICMP4_DST_MULTICAST);
}


void Icmp4Codec::ICMP4MiscTests (Packet *p)
{
    if ((p->dsize == 0) &&
        (p->icmph->type == icmp::IcmpType::ECHO_4))
        codec_events::decoder_event(p, DECODE_ICMP_PING_NMAP);

    if ((p->dsize == 0) &&
        (p->icmph->s_icmp_seq == 666))
        codec_events::decoder_event(p, DECODE_ICMP_ICMPENUM);

    if ((p->icmph->type == icmp::IcmpType::REDIRECT) &&
        (p->icmph->code == icmp::IcmpCode::REDIR_HOST))
        codec_events::decoder_event(p, DECODE_ICMP_REDIRECT_HOST);

    if ((p->icmph->type == icmp::IcmpType::REDIRECT) &&
        (p->icmph->code == icmp::IcmpCode::REDIR_NET))
        codec_events::decoder_event(p, DECODE_ICMP_REDIRECT_NET);

    if (p->icmph->type == icmp::IcmpType::ECHOREPLY)
    {
        int i;
        for (i = 0; i < p->ip_option_count; i++)
        {
            if (p->ip_options[i].is_opt_rr())
                codec_events::decoder_event(p, DECODE_ICMP_TRACEROUTE_IPOPTS);
        }
    }

    if ((p->icmph->type == icmp::IcmpType::SOURCE_QUENCH) &&
        (p->icmph->code == icmp::IcmpCode::SOURCE_QUENCH_CODE))
        codec_events::decoder_event(p, DECODE_ICMP_SOURCE_QUENCH);

    if ((p->dsize == 4) &&
        (p->icmph->type == icmp::IcmpType::ECHO_4) &&
        (p->icmph->s_icmp_seq == 0) &&
        (p->icmph->code == icmp::IcmpCode::ECHO_CODE))
        codec_events::decoder_event(p, DECODE_ICMP_BROADSCAN_SMURF_SCANNER);

    if ((p->icmph->type == icmp::IcmpType::DEST_UNREACH) &&
        (p->icmph->code == icmp::IcmpCode::PKT_FILTERED))
        codec_events::decoder_event(p, DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED);

    if ((p->icmph->type == icmp::IcmpType::DEST_UNREACH) &&
        (p->icmph->code == icmp::IcmpCode::PKT_FILTERED_HOST))
        codec_events::decoder_event(p, DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED);

    if ((p->icmph->type == icmp::IcmpType::DEST_UNREACH) &&
        (p->icmph->code == icmp::IcmpCode::PKT_FILTERED_NET))
        codec_events::decoder_event(p, DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED);
}

/******************************************************************
 *************************  L O G G E R  **************************
 ******************************************************************/

void Icmp4Codec::log(TextLog* const log, const uint8_t* raw_pkt,
                    const Packet* const)
{

    const icmp::ICMPHdr* const icmph = reinterpret_cast<const ICMPHdr *>(raw_pkt);

    /* 32 digits plus 7 colons and a NULL byte */
    char buf[8*4 + 7 + 1];
    TextLog_Print(log, "Type:%d  Code:%d  ", icmph->type, icmph->code);
    TextLog_Puts(log, "\n\t");


    switch(icmph->type)
    {
        case icmp::IcmpType::ECHOREPLY:
            TextLog_Print(log, "ID:%d  Seq:%d  ", ntohs(icmph->s_icmp_id),
                    ntohs(icmph->s_icmp_seq));
            TextLog_Puts(log, "ECHO REPLY");
            break;

        case icmp::IcmpType::DEST_UNREACH:
            TextLog_Puts(log, "DESTINATION UNREACHABLE: ");
            switch(icmph->code)
            {
                case icmp::IcmpCode::NET_UNREACH:
                    TextLog_Puts(log, "NET UNREACHABLE");
                    break;

                case icmp::IcmpCode::HOST_UNREACH:
                    TextLog_Puts(log, "HOST UNREACHABLE");
                    break;

                case icmp::IcmpCode::PROT_UNREACH:
                    TextLog_Puts(log, "PROTOCOL UNREACHABLE");
                    break;

                case icmp::IcmpCode::PORT_UNREACH:
                    TextLog_Puts(log, "PORT UNREACHABLE");
                    break;

                case icmp::IcmpCode::FRAG_NEEDED:
                    TextLog_Print(log, "FRAGMENTATION NEEDED, DF SET,"
                            " NEXT LINK MTU: %u",
                            ntohs(icmph->s_icmp_nextmtu));
                    break;

                case icmp::IcmpCode::SR_FAILED:
                    TextLog_Puts(log, "SOURCE ROUTE FAILED");
                    break;

                case icmp::IcmpCode::NET_UNKNOWN:
                    TextLog_Puts(log, "NET UNKNOWN");
                    break;

                case icmp::IcmpCode::HOST_UNKNOWN:
                    TextLog_Puts(log, "HOST UNKNOWN");
                    break;

                case icmp::IcmpCode::HOST_ISOLATED:
                    TextLog_Puts(log, "HOST ISOLATED");
                    break;

                case icmp::IcmpCode::PKT_FILTERED_NET:
                    TextLog_Puts(log, "ADMINISTRATIVELY PROHIBITED NETWORK FILTERED");
                    break;

                case icmp::IcmpCode::PKT_FILTERED_HOST:
                    TextLog_Puts(log, "ADMINISTRATIVELY PROHIBITED HOST FILTERED");
                    break;

                case icmp::IcmpCode::NET_UNR_TOS:
                    TextLog_Puts(log, "NET UNREACHABLE FOR TOS");
                    break;

                case icmp::IcmpCode::HOST_UNR_TOS:
                    TextLog_Puts(log, "HOST UNREACHABLE FOR TOS");
                    break;

                case icmp::IcmpCode::PKT_FILTERED:
                    TextLog_Puts(log, "ADMINISTRATIVELY PROHIBITED, PACKET FILTERED");
                    break;

                case icmp::IcmpCode::PREC_VIOLATION:
                    TextLog_Puts(log, "PREC VIOLATION");
                    break;

                case icmp::IcmpCode::PREC_CUTOFF:
                    TextLog_Puts(log, "PREC CUTOFF");
                    break;

                default:
                    TextLog_Puts(log, "UNKNOWN");
                    break;

            }
            break;

        case icmp::IcmpType::SOURCE_QUENCH:
            TextLog_Puts(log, "SOURCE QUENCH");
            break;

        case icmp::IcmpType::REDIRECT:
            TextLog_Puts(log, "REDIRECT");
            switch(icmph->code)
            {
                case icmp::IcmpCode::REDIR_NET:
                    TextLog_Puts(log, " NET");
                    break;

                case icmp::IcmpCode::REDIR_HOST:
                    TextLog_Puts(log, " HOST");
                    break;

                case icmp::IcmpCode::REDIR_TOS_NET:
                    TextLog_Puts(log, " TOS NET");
                    break;

                case icmp::IcmpCode::REDIR_TOS_HOST:
                    TextLog_Puts(log, " TOS HOST");
                    break;

                default:
                    break;
            }

/* written this way since inet_ntoa was typedef'ed to use sfip_ntoa
 * which requires sfip_t instead of inaddr's.  This call to inet_ntoa
 * is a rare case that doesn't use sfip_t's. */

// XXX-IPv6 NOT YET IMPLEMENTED - IPV6 addresses technically not supported - need to change ICMP

            /* no inet_ntop in Windows */
            sfip_raw_ntop(AF_INET, (const void *)(&icmph->s_icmp_gwaddr.s_addr),
                          buf, sizeof(buf));
            TextLog_Print(log, " NEW GW: %s", buf);
            break;

        case icmp::IcmpType::ECHO_4:
            TextLog_Print(log, "ID:%d   Seq:%d  ", ntohs(icmph->s_icmp_id),
                    ntohs(icmph->s_icmp_seq));
            TextLog_Puts(log, "ECHO");
            break;

        case icmp::IcmpType::ROUTER_ADVERTISE:
            TextLog_Print(log, "ROUTER ADVERTISMENT: "
                    "Num addrs: %d Addr entry size: %d Lifetime: %u",
                    icmph->s_icmp_num_addrs, icmph->s_icmp_wpa,
                    ntohs(icmph->s_icmp_lifetime));
            break;

        case icmp::IcmpType::ROUTER_SOLICIT:
            TextLog_Puts(log, "ROUTER SOLICITATION");
            break;

        case icmp::IcmpType::TIME_EXCEEDED:
            TextLog_Puts(log, "TTL EXCEEDED");
            switch(icmph->code)
            {
                case icmp::IcmpCode::TIMEOUT_TRANSIT:
                    TextLog_Puts(log, " IN TRANSIT");
                    break;

                case icmp::IcmpCode::TIMEOUT_REASSY:
                    TextLog_Puts(log, " TIME EXCEEDED IN FRAG REASSEMBLY");
                    break;

                default:
                    break;
            }

            break;

        case icmp::IcmpType::PARAMETERPROB:
            TextLog_Puts(log, "PARAMETER PROBLEM");
            switch(icmph->code)
            {
                case icmp::IcmpCode::PARAM_BADIPHDR:
                    TextLog_Print(log, ": BAD IP HEADER BYTE %u",
                            icmph->s_icmp_pptr);
                    break;

                case icmp::IcmpCode::PARAM_OPTMISSING:
                    TextLog_Puts(log, ": OPTION MISSING");
                    break;

                case icmp::IcmpCode::PARAM_BAD_LENGTH:
                    TextLog_Puts(log, ": BAD LENGTH");
                    break;

                default:
                    break;
            }

            break;

        case icmp::IcmpType::TIMESTAMP:
            TextLog_Print(log, "ID: %u  Seq: %u  TIMESTAMP REQUEST",
                    ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq));
            break;

        case icmp::IcmpType::TIMESTAMPREPLY:
            TextLog_Print(log, "ID: %u  Seq: %u  TIMESTAMP REPLY: "
                    "Orig: %u Rtime: %u  Ttime: %u",
                    ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq),
                    icmph->s_icmp_otime, icmph->s_icmp_rtime,
                    icmph->s_icmp_ttime);
            break;

        case icmp::IcmpType::INFO_REQUEST:
            TextLog_Print(log, "ID: %u  Seq: %u  INFO REQUEST",
                    ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq));
            break;

        case icmp::IcmpType::INFO_REPLY:
            TextLog_Print(log, "ID: %u  Seq: %u  INFO REPLY",
                    ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq));
            break;

        case icmp::IcmpType::ADDRESS:
            TextLog_Print(log, "ID: %u  Seq: %u  ADDRESS REQUEST",
                    ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq));
            break;

        case icmp::IcmpType::ADDRESSREPLY:
            TextLog_Print(log, "ID: %u  Seq: %u  ADDRESS REPLY: 0x%08X",
                    ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq),
                    (u_int) ntohl(icmph->s_icmp_mask));
            break;

        default:
            TextLog_Puts(log, "UNKNOWN");

            break;
    }
}

/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/

namespace
{

struct IcmpHdr {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint32_t unused;
} ;

} // namespace



bool Icmp4Codec::encode(EncState* enc, Buffer* out, const uint8_t* /*raw_in*/)
{
    // FIXIT-J:  speak with Russ, then get rid of commented lines
//    uint8_t* p;
    IcmpHdr* ho;

    if (!update_buffer(out, sizeof(*ho)))
        return false;

//    const uint16_t *hi = reinterpret_cast<const uint16_t*>(raw_in);
    ho = reinterpret_cast<IcmpHdr*>(out->base);

    enc->proto = IPPROTO_ID_ICMPV4;
    ho->type = icmp::IcmpType::DEST_UNREACH;
    ho->code = ip_util::get_icmp4_code(enc->type);
    ho->cksum = 0;
    ho->unused = 0;

#if 0
    // copy original ip header
    p = out->base + sizeof(IcmpHdr);
    memcpy(p, enc->ip_hdr, enc->ip_len);

    // Now performed in cd_prot_embedded_in_icmp.cc

    // copy first 8 octets of original ip data (ie udp header)
    p += enc->ip_len;
    memcpy(p, hi, icmp::ICMP_UNREACH_DATA_LEN);
#endif

    ho->cksum = checksum::icmp_cksum((uint16_t *)ho, buff_diff(out, (uint8_t *)ho));

    return true;
}

bool Icmp4Codec::update(Packet* p, Layer* lyr, uint32_t* len)
{
    IcmpHdr* h = (IcmpHdr*)(lyr->start);

    // This function will not be called if encoding unreachables
    *len += sizeof(*h) + p->dsize;


    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        h->cksum = 0;
        h->cksum = checksum::icmp_cksum((uint16_t *)h, *len);
    }

    return true;
}

void Icmp4Codec::format(EncodeFlags, const Packet*, Packet* c, Layer* lyr)
{
    // TBD handle nested icmp4 layers
    c->icmph = (ICMPHdr*)lyr->start;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Module* mod_ctor()
{
    return new Icmp4Module;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Codec *ctor(Module*)
{
    return new Icmp4Codec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi icmp4_api =
{
    {
        PT_CODEC,
        CD_ICMP4_NAME,
        CD_ICMP4_HELP,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &icmp4_api.base,
    nullptr
};
#else
const BaseApi* cd_icmp4 = &icmp4_api.base;
#endif
