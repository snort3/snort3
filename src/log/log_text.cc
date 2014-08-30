/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// @file    log_text.c
// @author  Russ Combs <rcombs@sourcefire.com>

#include "log_text.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "log.h"
#include "rules.h"
#include "treenodes.h"
#include "util.h"
#include "snort_debug.h"
#include "signature.h"
#include "util_net.h"
#include "protocols/packet.h"
#include "snort.h"
#include "log/text_log.h"
#include "snort_bounds.h"
#include "obfuscation.h"
#include "detection_util.h"
#include "packet_io/sfdaq.h"
#include "protocols/layer.h"
#include "service_inspectors/http_inspect/hi_main.h"

#include "sfip/sf_ip.h"

#include "protocols/eth.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/icmp6.h"
#include "protocols/icmp4.h"
#include "protocols/udp.h"
#include "protocols/tcp.h"
#include "protocols/gre.h"
#include "protocols/token_ring.h"
#include "protocols/wlan.h"
#include "protocols/linux_sll.h"
#include "protocols/eapol.h"

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

/*--------------------------------------------------------------------
 * utility functions
 *--------------------------------------------------------------------
 */
void LogTimeStamp(TextLog* log, Packet* p)
{
    char timestamp[TIMEBUF_SIZE];
    ts_print((struct timeval*)&p->pkth->ts, timestamp);
    TextLog_Puts(log, timestamp);
}

/*--------------------------------------------------------------------
 * alert stuff cloned from log.c
 *--------------------------------------------------------------------
 */
/*--------------------------------------------------------------------
 * Function: LogPriorityData()
 *
 * Purpose: Prints out priority data associated with an alert
 *
 * Arguments: log => pointer to TextLog to write the data to
 *            doNewLine => tack a \n to the end of the line or not (bool)
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
void LogPriorityData(TextLog* log, const Event* e, bool doNewLine)
{
    if ((e->sig_info->classType != NULL)
            && (e->sig_info->classType->name != NULL))
    {
        TextLog_Print(log, "[Classification: %s] ",
                e->sig_info->classType->name);
    }

    TextLog_Print(log, "[Priority: %d] ", e->sig_info->priority);

    if (doNewLine)
        TextLog_NewLine(log);
}

/*--------------------------------------------------------------------
 * Layer 2 header stuff cloned from log.c
 *--------------------------------------------------------------------
 */
/*--------------------------------------------------------------------
 * Function: LogTrHeader(TextLog*, Packet*)
 *
 * Purpose: Print the packet TokenRing header to the given TextLog
 *
 * Arguments: log => pointer to TextLog to print to
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */

void LogTrHeader(TextLog* log, Packet* p)
{
    const token_ring::Trh_hdr* trh =
        reinterpret_cast<const token_ring::Trh_hdr*>(layer::get_root_layer(p));

    TextLog_Print(log, "%X:%X:%X:%X:%X:%X -> ", trh->saddr[0],
            trh->saddr[1], trh->saddr[2], trh->saddr[3],
            trh->saddr[4], trh->saddr[5]);
    TextLog_Print(log, "%X:%X:%X:%X:%X:%X\n", trh->daddr[0],
            trh->daddr[1], trh->daddr[2], trh->daddr[3],
            trh->daddr[4], trh->daddr[5]);

    const token_ring::Trh_llc* trhllc =
        reinterpret_cast<const token_ring::Trh_llc*>(trh + sizeof(*trh));

    TextLog_Print(log, "access control:0x%X frame control:0x%X\n", trh->ac,
            trh->fc);

    TextLog_Print(log, "DSAP: 0x%X SSAP 0x%X protoID: %X%X%X Ethertype: %X\n",
            trhllc->dsap, trhllc->ssap, trhllc->protid[0],
            trhllc->protid[1], trhllc->protid[2], trhllc->ethertype);


    const token_ring::Trh_mr* trhmr = token_ring::get_trhmr(trhllc);

    if(trhmr)
    {
        TextLog_Print(log, "RIF structure is present:\n");
        TextLog_Print(log, "bcast: 0x%X length: 0x%X direction: 0x%X largest"
                "fr. size: 0x%X res: 0x%X\n",
                TRH_MR_BCAST(trhmr), TRH_MR_LEN(trhmr),
        TRH_MR_DIR(trhmr), TRH_MR_LF(trhmr),
                TRH_MR_RES(trhmr));
        TextLog_Print(log, "rseg -> %X:%X:%X:%X:%X:%X:%X:%X\n",
                trhmr->rseg[0], trhmr->rseg[1], trhmr->rseg[2],
                trhmr->rseg[3], trhmr->rseg[4], trhmr->rseg[5],
                trhmr->rseg[6], trhmr->rseg[7]);
    }
}

/*--------------------------------------------------------------------
 * Function: LogEthHeader()
 *
 * Purpose: Print the packet Ethernet header to the given TextLog
 *
 * Arguments: log => pointer to TextLog to print to
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
static void LogEthHeader(TextLog* log, Packet* p)
{
    const eth::EtherHdr *eh = layer::get_eth_layer(p);

    /* src addr */
    TextLog_Print(log, "%02X:%02X:%02X:%02X:%02X:%02X -> ", eh->ether_src[0],
        eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
        eh->ether_src[4], eh->ether_src[5]);

    /* dest addr */
    TextLog_Print(log, "%02X:%02X:%02X:%02X:%02X:%02X ", eh->ether_dst[0],
        eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
        eh->ether_dst[4], eh->ether_dst[5]);

    /* protocol and pkt size */
    TextLog_Print(log, "type:0x%X len:0x%X\n", ntohs(eh->ether_type),
        p->pkth->pktlen);
}

static void LogMPLSHeader(TextLog* log, Packet* p)
{

    TextLog_Print(log,"label:0x%05X exp:0x%X bos:0x%X ttl:0x%X\n",
        p->mplsHdr.label, p->mplsHdr.exp, p->mplsHdr.bos, p->mplsHdr.ttl);
}

static void LogGREHeader(TextLog *log, Packet *p)
{
    const gre::GREHdr *greh = layer::get_gre_layer(p);

    if (greh == NULL)
        return;

    TextLog_Print(log, "GRE version:%u flags:0x%02X ether-type:0x%04X\n",
            greh->get_version(), greh->flags, greh->get_proto());
}

/*--------------------------------------------------------------------
 * Function: LogSLLHeader(TextLog* )
 *
 * Purpose: Print the packet SLL (fake) header to the given TextLog
 * (piece partly is borrowed from tcpdump :))
 *
 * Arguments: log => pointer to TextLog to print to
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
#ifdef DLT_LINUX_SLL
static void LogSLLHeader(TextLog* log, Packet* p)
{
    const linux_sll::SLLHdr* sllh =
        reinterpret_cast<const linux_sll::SLLHdr*>(layer::get_root_layer(p));

    switch (ntohs(sllh->sll_pkttype)) {
        case LINUX_SLL_HOST:
            TextLog_Puts(log, "< ");
            break;
        case LINUX_SLL_BROADCAST:
            TextLog_Puts(log, "B ");
            break;
        case LINUX_SLL_MULTICAST:
            TextLog_Puts(log, "M ");
            break;
        case LINUX_SLL_OTHERHOST:
            TextLog_Puts(log, "P ");
            break;
        case LINUX_SLL_OUTGOING:
            TextLog_Puts(log, "> ");
            break;
        default:
            TextLog_Puts(log, "? ");
            break;
        }

    /* mac addr */
    TextLog_Print(log, "l/l len: %i l/l type: 0x%X %02X:%02X:%02X:%02X:%02X:%02X\n",
        htons(sllh->sll_halen), ntohs(sllh->sll_hatype),
        sllh->sll_addr[0], sllh->sll_addr[1], sllh->sll_addr[2],
        sllh->sll_addr[3], sllh->sll_addr[4], sllh->sll_addr[5]);

    /* protocol and pkt size */
    TextLog_Print(log, "pkt type:0x%X proto: 0x%X len:0x%X\n",
        ntohs(sllh->sll_pkttype),
        ntohs(sllh->sll_protocol), p->pkth->pktlen);
}
#endif

/*--------------------------------------------------------------------
 * Function: LogWifiHeader(TextLog* )
 *
 * Purpose: Print the packet 802.11 header to the given TextLog
 *
 * Arguments: log => pointer to TextLog to print to
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
static void LogWifiHeader(TextLog* log, Packet * p)
{
  const wlan::WifiHdr *wifih =
      reinterpret_cast< const wlan::WifiHdr *>(layer::get_root_layer(p));

  /* This assumes we are printing a data packet, could be changed
     to print other types as well */
  const uint8_t *da = NULL, *sa = NULL, *bssid = NULL, *ra = NULL,
    *ta = NULL;
  /* per table 4, IEEE802.11 section 7.2.2 */
  if ((wifih->frame_control & WLAN_FLAG_TODS) &&
      (wifih->frame_control & WLAN_FLAG_FROMDS)) {
    ra = wifih->addr1;
    ta = wifih->addr2;
    da = wifih->addr3;
    sa = wifih->addr4;
  }
  else if (wifih->frame_control & WLAN_FLAG_TODS) {
    bssid = wifih->addr1;
    sa = wifih->addr2;
    da = wifih->addr3;
  }
  else if (wifih->frame_control & WLAN_FLAG_FROMDS) {
    da = wifih->addr1;
    bssid = wifih->addr2;
    sa = wifih->addr3;
  }
  else {
    da = wifih->addr1;
    sa = wifih->addr2;
    bssid = wifih->addr3;
  }

  /* DO this switch to provide additional info on the type */
  switch(wifih->frame_control & 0x00ff)
  {
  case WLAN_TYPE_MGMT_BEACON:
    TextLog_Puts(log, "Beacon ");
    break;
    /* management frames */
  case WLAN_TYPE_MGMT_ASREQ:
    TextLog_Puts(log, "Assoc. Req. ");
    break;
  case WLAN_TYPE_MGMT_ASRES:
    TextLog_Puts(log, "Assoc. Resp. ");
    break;
  case WLAN_TYPE_MGMT_REREQ:
    TextLog_Puts(log, "Reassoc. Req. ");
    break;
  case WLAN_TYPE_MGMT_RERES:
    TextLog_Puts(log, "Reassoc. Resp. ");
    break;
  case WLAN_TYPE_MGMT_PRREQ:
    TextLog_Puts(log, "Probe Req. ");
    break;
  case WLAN_TYPE_MGMT_PRRES:
    TextLog_Puts(log, "Probe Resp. ");
    break;
  case WLAN_TYPE_MGMT_ATIM:
    TextLog_Puts(log, "ATIM ");
    break;
  case WLAN_TYPE_MGMT_DIS:
    TextLog_Puts(log, "Dissassoc. ");
    break;
  case WLAN_TYPE_MGMT_AUTH:
    TextLog_Puts(log, "Authent. ");
    break;
  case WLAN_TYPE_MGMT_DEAUTH:
    TextLog_Puts(log, "Deauthent. ");
    break;

    /* Control frames */
  case WLAN_TYPE_CONT_PS:
  case WLAN_TYPE_CONT_RTS:
  case WLAN_TYPE_CONT_CTS:
  case WLAN_TYPE_CONT_ACK:
  case WLAN_TYPE_CONT_CFE:
  case WLAN_TYPE_CONT_CFACK:
    TextLog_Puts(log, "Control ");
    break;
  }

  if (sa != NULL) {
    TextLog_Print(log, "%X:%X:%X:%X:%X:%X -> ", sa[0],
        sa[1], sa[2], sa[3], sa[4], sa[5]);
  }
  else if (ta != NULL) {
    TextLog_Print(log, "ta: %X:%X:%X:%X:%X:%X da: ", ta[0],
        ta[1], ta[2], ta[3], ta[4], ta[5]);
  }

  TextLog_Print(log, "%X:%X:%X:%X:%X:%X\n", da[0],
      da[1], da[2], da[3], da[4], da[5]);

  if (bssid != NULL)
  {
      TextLog_Print(log, "bssid: %X:%X:%X:%X:%X:%X", bssid[0],
              bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  }

  if (ra != NULL) {
    TextLog_Print(log, " ra: %X:%X:%X:%X:%X:%X", ra[0],
        ra[1], ra[2], ra[3], ra[4], ra[5]);
  }
  TextLog_Puts(log, " Flags:");
  if (wifih->frame_control & WLAN_FLAG_TODS)    TextLog_Puts(log," ToDs");
  if (wifih->frame_control & WLAN_FLAG_TODS)    TextLog_Puts(log," FrDs");
  if (wifih->frame_control & WLAN_FLAG_FRAG)    TextLog_Puts(log," Frag");
  if (wifih->frame_control & WLAN_FLAG_RETRY)   TextLog_Puts(log," Re");
  if (wifih->frame_control & WLAN_FLAG_PWRMGMT) TextLog_Puts(log," Pwr");
  if (wifih->frame_control & WLAN_FLAG_MOREDAT) TextLog_Puts(log," MD");
  if (wifih->frame_control & WLAN_FLAG_WEP)     TextLog_Puts(log," Wep");
  if (wifih->frame_control & WLAN_FLAG_ORDER)   TextLog_Puts(log," Ord");
  TextLog_NewLine(log);
}

/*--------------------------------------------------------------------
 * Function: Log2ndHeader(TextLog* , Packet p)
 *
 * Purpose: Log2ndHeader -- prints second layber  header info.
 *
 * Arguments: log => pointer to TextLog to print to
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
void Log2ndHeader(TextLog* log, Packet* p)
{

    switch(DAQ_GetBaseProtocol())
    {
        case DLT_EN10MB:        /* Ethernet */
            if(p && (p->num_layers > 0))
                LogEthHeader(log, p);
            break;
#ifdef DLT_IEEE802_11
        case DLT_IEEE802_11:
            if(p && (p->num_layers > 0))
                LogWifiHeader(log, p);
            break;
#endif
        case DLT_IEEE802:                /* Token Ring */
            if(p && (p->num_layers > 0))
                LogTrHeader(log, p);
            break;
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            if (p && (p->num_layers > 0))
                LogSLLHeader(log, p);  /* Linux cooked sockets */
            break;
#endif
        default:
            if (ScLogVerbose())
            {
                // FIXIT-L should only be output once!
                ErrorMessage("Datalink %i type 2nd layer display is not "
                             "supported\n", DAQ_GetBaseProtocol());
            }
    }
}

/*-------------------------------------------------------------------
 * IP stuff cloned from log.c
 *-------------------------------------------------------------------
 */

void LogIpOptions(TextLog*  log, const Packet* const p)
{
    uint8_t i, j;
    u_long init_offset;
    u_long print_offset;
    const uint8_t option_count = p->ip_option_count;

    init_offset = TextLog_Tell(log);
    TextLog_Print(log, "IP Options (%d) => ", option_count);

    for(i = 0; i < option_count; i++)
    {
        print_offset = TextLog_Tell(log);

        if((print_offset - init_offset) > 60)
        {
            TextLog_Puts(log, "\nIP Options => ");
            init_offset = TextLog_Tell(log);
        }

        switch(p->ip_options[i].code)
        {
            case IPOPT_RR:
                TextLog_Puts(log, "RR ");
                break;

            case IPOPT_EOL:
                TextLog_Puts(log, "EOL ");
                break;

            case IPOPT_NOP:
                TextLog_Puts(log, "NOP ");
                break;

            case IPOPT_TS:
                TextLog_Puts(log, "TS ");
                break;

            case IPOPT_ESEC:
                TextLog_Puts(log, "ESEC ");
                break;

            case IPOPT_SECURITY:
                TextLog_Puts(log, "SEC ");
                break;

            case IPOPT_LSRR:
            case IPOPT_LSRR_E:
                TextLog_Puts(log, "LSRR ");
                break;

            case IPOPT_SATID:
                TextLog_Puts(log, "SID ");
                break;

            case IPOPT_SSRR:
                TextLog_Puts(log, "SSRR ");
                break;

            case IPOPT_RTRALT:
                TextLog_Puts(log, "RTRALT ");
                break;

            default:
                TextLog_Print(log, "Opt %d: ", p->ip_options[i].code);

                const ip::IpOptions* const ip_opt = &(p->ip_options[i]);
                const uint8_t opt_len = ip_opt->len;

                if(opt_len)
                {
                    if (ip_opt->data)
                    {
                        for(j = 0; (j + 1) < opt_len; j += 2)
                        {
                            TextLog_Print(log, "%02X%02X ",ip_opt->data[j],
                                                           ip_opt->data[j+1]);
                        }

                        // since we're skipping by two, if (j+1) == opt_len,
                        // we will not have printed j
                        if (j < opt_len)
                            TextLog_Print(log, "%02X",ip_opt->data[j]);
                    }
                    else
                    {
                        for(j = 0; (j + 1) < opt_len; j += 2)
                        {
                            TextLog_Print(log, "%02X%02X ", 0, 0);
                        }

                        // since we're skipping by two, if (j+1) == opt_len,
                        // we will not have printed j
                        if (j < opt_len)
                            TextLog_Print(log, "%02X",0);
                    }
                }
                break;
        }
    }
    TextLog_NewLine(log);
}

/*--------------------------------------------------------------------
 * Function: LogIPAddrs(TextLog* )
 *
 * Purpose: Dump the IP addresses to the given TextLog
 *          Handles obfuscation
 *
 * Arguments: log => TextLog to print to
 *            p => packet structure
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
void LogIpAddrs(TextLog *log, Packet *p)
{
    if (!p->ip_api.is_valid())
        return;

    if ((p->decode_flags & DECODE__FRAG)
            || ((p->ip_api.proto() != IPPROTO_TCP)
                && (p->ip_api.proto() != IPPROTO_UDP)))
    {
        const char *ip_fmt = "%s -> %s";

        if (ScObfuscate())
        {
            TextLog_Print(log, ip_fmt,
                    ObfuscateIpToText(p->ip_api.get_src()),
                    ObfuscateIpToText(p->ip_api.get_dst()));
        }
        else
        {
            TextLog_Print(log, ip_fmt,
                    inet_ntoax(p->ip_api.get_src()),
                    inet_ntoax((p->ip_api.get_dst())));
        }
    }
    else
    {
        const char *ip_fmt = "%s:%d -> %s:%d";

        if (ScObfuscate())
        {
            TextLog_Print(log, ip_fmt,
                    ObfuscateIpToText(p->ip_api.get_src()), p->sp,
                    ObfuscateIpToText(p->ip_api.get_dst()), p->dp);
        }
        else
        {
            TextLog_Print(log, ip_fmt,
                    inet_ntoax(p->ip_api.get_src()), p->sp,
                    inet_ntoax(p->ip_api.get_dst()), p->dp);
        }
    }
}

/*--------------------------------------------------------------------
 * Function: LogIPHeader(TextLog* )
 *
 * Purpose: Dump the IP header info to the given TextLog
 *
 * Arguments: log => TextLog to print to
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
void LogIPHeader(TextLog*  log, Packet * p)
{
    if(!p->ip_api.is_valid())
    {
        TextLog_Print(log, "IP header truncated\n");
        return;
    }

    LogIpAddrs(log, p);

    if(!ScOutputDataLink())
    {
        TextLog_NewLine(log);
    }
    else
    {
        TextLog_Putc(log, ' ');
    }

    TextLog_Print(log, "%s TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u",
            protocol_names[p->ip_api.proto()],
            p->ip_api.ttl(),
            p->ip_api.tos(),
            p->ip_api.is_ip6() ? ntohl(p->ip_api.id(p)) : ntohs((uint16_t)p->ip_api.id(p)),
            p->ip_api.hlen() << 2,
            p->ip_api.dgram_len());

    /* print the reserved bit if it's set */
    if((uint8_t)((ntohs(p->ip_api.off(p)) & 0x8000) >> 15) == 1)
        TextLog_Puts(log, " RB");

    /* printf more frags/don't frag bits */
    if((uint8_t)((ntohs(p->ip_api.off(p)) & 0x4000) >> 14) == 1)
        TextLog_Puts(log, " DF");

    if((uint8_t)((ntohs(p->ip_api.off(p)) & 0x2000) >> 13) == 1)
        TextLog_Puts(log, " MF");

    TextLog_NewLine(log);

    /* print IP options */
    if(p->ip_option_count != 0)
    {
        LogIpOptions(log, p);
    }

    /* print fragment info if necessary */
    if(p->decode_flags & DECODE__FRAG)
    {
        TextLog_Print(log, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
                (p->frag_offset & 0x1FFF),
                p->ip_api.pay_len());
    }
}

static void LogOuterIPHeader(TextLog *log, Packet *p)
{
    uint8_t save_ip_option_count = p->ip_option_count;
    uint8_t save_frag_flag = (p->decode_flags & DECODE__FRAG);
    uint16_t save_sp, save_dp;
    ip::IpApi save_ip_api = p->ip_api;

    p->ip_option_count = 0;
    p->decode_flags &= ~DECODE__FRAG;

    if (p->proto_bits & PROTO_BIT__TEREDO)
    {
        save_sp = p->sp;
        save_dp = p->dp;

        const udp::UDPHdr *udph = layer::get_outer_udp_lyr(p);
        p->sp = ntohs(udph->uh_sport);
        p->dp = ntohs(udph->uh_dport);

        LogIPHeader(log, p);

        p->sp = save_sp;
        p->dp = save_dp;
    }
    else
        LogIPHeader(log, p);

    p->ip_api = save_ip_api;
    p->ip_option_count = save_ip_option_count;
    p->decode_flags |= save_frag_flag;
}

/*-------------------------------------------------------------------
 * TCP stuff cloned from log.c
 *-------------------------------------------------------------------
 */
inline uint16_t extract_16_bits(const uint8_t* const buf)
{ return ntohs(* ((uint16_t*)(buf)) ); }

inline uint32_t extract_32_bits(const uint8_t* const buf)
{ return ntohl(* ((uint32_t*)(buf)) ); }

void LogTcpOptions(TextLog*  log, const Packet* const p)
{
    uint8_t i;
    int j;
    const uint8_t option_count = p->tcp_option_count;
    const Options* const opts = p->tcp_options;

    TextLog_Print(log, "TCP Options (%d) => ", option_count);

    for(i = 0; i < option_count; i++)
    {
#if 0
        print_offset = TextLog_Tell(log);

        if((print_offset - init_offset) > 60)
        {
            TextLog_Puts(log, "\nTCP Options => ");
            init_offset = TextLog_Tell(log);
        }
#endif
        switch(opts[i].code)
        {
            case TCPOPT_MAXSEG:
            {
                uint16_t val;
                TextLog_Puts(log, "MSS: ");

                if (opts[i].data)
                    val = extract_16_bits(opts[i].data);
                else
                    val = 0;

                TextLog_Print(log, "%u ", val);
                break;
            }
            case TCPOPT_EOL:
                TextLog_Puts(log, "EOL ");
                break;

            case TCPOPT_NOP:
                TextLog_Puts(log, "NOP ");
                break;

            case TCPOPT_WSCALE:
            {
                uint8_t val;

                if (opts[i].data)
                    val = opts[i].data[0];
                else
                    val = 0;

                TextLog_Print(log, "WS: %u ", val);
                break;
            }
            case TCPOPT_SACK:
            {
                uint16_t val1, val2;

                if (opts[i].data && (opts[i].len >= 4))
                {
                    val1 = extract_16_bits(opts[i].data);
                    val2 = extract_16_bits(opts[i].data + 2);
                }
                else if (opts[i].data && (opts[i].len >= 2))
                {
                    val1 = extract_16_bits(opts[i].data);
                    val2 = 0;
                }
                else
                {
                    val1 = 0;
                    val2 = 0;
                }

                TextLog_Print(log, "Sack: %u@%u", val1, val2);
                break;
            }
            case TCPOPT_SACKOK:
                TextLog_Puts(log, "SackOK ");
                break;

            case TCPOPT_ECHO:
            {
                uint32_t val;

                if (opts[i].data)
                    val = extract_32_bits(opts[i].data);
                else
                    val = 0;

                TextLog_Print(log, "Echo: %u ", val);
                break;
            }
            case TCPOPT_ECHOREPLY:
            {
                uint32_t val;

                if (opts[i].data)
                    val = extract_32_bits(opts[i].data);
                else
                    val = 0;

                TextLog_Print(log, "Echo Rep: %u ", val);
                break;
            }
            case TCPOPT_TIMESTAMP:
            {
                uint32_t val1, val2;

                if (opts[i].data)
                {
                    val1 = extract_32_bits(opts[i].data);
                    val2 = extract_32_bits(opts[i].data + 4);
                }
                else
                {
                    val1 = 0;
                    val2 = 0;
                }
                TextLog_Print(log, "TS: %u %u ", val1, val2);
                break;
            }
            case TCPOPT_CC:
            {
                uint32_t val;

                if (opts[i].data)
                    val = extract_32_bits(opts[i].data);
                else
                    val = 0;

                TextLog_Print(log, "CC %u ", val);
                break;
            }
            case TCPOPT_CC_NEW:
            {
                uint32_t val;

                if (opts[i].data)
                    val = extract_32_bits(opts[i].data);
                else
                    val = 0;

                TextLog_Print(log, "CCNEW: %u ", val);
                break;
            }
            case TCPOPT_CC_ECHO:
            {
                uint32_t val;

                if (opts[i].data)
                    val = extract_32_bits(opts[i].data);
                else
                    val = 0;

                TextLog_Print(log, "CCECHO: %u ", val);
                break;
            }
            default:
            {
                const uint8_t opts_len = opts[i].len;

                if(opts_len)
                {
                    TextLog_Print(log, "Opt %d (%d): ", opts[i].code,
                            (int) opts_len);

                    if (opts[i].data)
                    {
                        for(j = 0; (j +1) < opts_len; j += 2)
                        {
                            TextLog_Print(log, "%02X%02X ",  opts[i].data[j],
                                                             opts[i].data[j+1]);
                        }

                        if (j < opts_len)
                            TextLog_Print(log, "%02x", opts[i].data[j]);
                    }
                    else
                    {
                        for(j = 0; (j +1) < opts_len; j += 2)
                        {
                            TextLog_Print(log, "%02X%02X ", 0, 0);
                        }

                        if (j < opts_len)
                            TextLog_Print(log, "%02x", opts[i].data[j]);
                    }

                    TextLog_Putc(log, ' ');
                }
                else
                {
                    TextLog_Print(log, "Opt %d ", p->tcp_options[i].code);
                }
                break;
            }
        }
    }
    TextLog_NewLine(log);
}


/*--------------------------------------------------------------------
 * Function: LogTCPHeader(TextLog* )
 *
 * Purpose: Dump the TCP header info to the given TextLog
 *
 * Arguments: log => pointer to TextLog to print data to
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
void LogTCPHeader(TextLog*  log, Packet * p)
{
    char tcpFlags[9];

    if(p->tcph == NULL)
    {
        TextLog_Print(log, "TCP header truncated\n");
        return;
    }
    /* print TCP flags */
    CreateTCPFlagString(p->tcph, tcpFlags);
    TextLog_Puts(log, tcpFlags); /* We don't care about the NULL */

    /* print other TCP info */
    TextLog_Print(log, " Seq: 0x%lX  Ack: 0x%lX  Win: 0x%X  TcpLen: %d",
            (u_long) ntohl(p->tcph->th_seq),
            (u_long) ntohl(p->tcph->th_ack),
            ntohs(p->tcph->th_win), TCP_OFFSET(p->tcph) << 2);

    if((p->tcph->th_flags & TH_URG) != 0)
    {
        TextLog_Print(log, "  UrgPtr: 0x%X\n", (uint16_t) ntohs(p->tcph->th_urp));
    }
    else
    {
        TextLog_NewLine(log);
    }

    /* dump the TCP options */
    if(p->tcp_option_count != 0)
    {
        LogTcpOptions(log, p);
    }
}

/*-------------------------------------------------------------------
 * UDP stuff cloned from log.c
 *-------------------------------------------------------------------
 */
/*--------------------------------------------------------------------
 * Function: LogUDPHeader(TextLog* )
 *
 * Purpose: Dump the UDP header to the given TextLog
 *
 * Arguments: log => pointer to TextLog
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
void LogUDPHeader(TextLog* log, Packet* p)
{

    if(p->udph == NULL)
    {
        TextLog_Print(log, "UDP header truncated\n");
        return;
    }
    /* not much to do here... */
    TextLog_Print(log, "Len: %d\n", ntohs(p->udph->uh_len) - udp::UDP_HEADER_LEN);
}

/*--------------------------------------------------------------------
 * ICMP stuff cloned from log.c
 *--------------------------------------------------------------------
 */
/*--------------------------------------------------------------------
 * Function: LogEmbeddedICMPHeader(TextLog* , ICMPHdr *)
 *
 * Purpose: Prints the 64 bits of the original IP payload in an ICMP packet
 *          that requires it
 *
 * Arguments: log => pointer to TextLog
 *            icmph  => ICMPHdr struct pointing to original ICMP
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
static void LogEmbeddedICMPHeader(TextLog* log, const ICMPHdr *icmph)
{
    if (log == NULL || icmph == NULL)
        return;

    TextLog_Print(log, "Type: %d  Code: %d  Csum: %u",
            icmph->type, icmph->code, ntohs(icmph->csum));

    switch (icmph->type)
    {
        case ICMP_DEST_UNREACH:
        case ICMP_TIME_EXCEEDED:
        case ICMP_SOURCE_QUENCH:
            break;

        case ICMP_PARAMETERPROB:
            if (icmph->code == 0)
                TextLog_Print(log, "  Ptr: %u", icmph->s_icmp_pptr);
            break;

        case ICMP_REDIRECT:
// XXX-IPv6 "NOT YET IMPLEMENTED - ICMP printing"
            break;

        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
            TextLog_Print(log, "  Id: %u  SeqNo: %u",
                    ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq));
            break;

        case ICMP_ROUTER_ADVERTISE:
            TextLog_Print(log, "  Addrs: %u  Size: %u  Lifetime: %u",
                    icmph->s_icmp_num_addrs, icmph->s_icmp_wpa,
                    ntohs(icmph->s_icmp_lifetime));
            break;

        default:
            break;
    }

    TextLog_NewLine(log);

    return;
}

/*--------------------------------------------------------------------
 * Function: LogICMPEmbeddedIP(TextLog* , Packet *)
 *
 * Purpose: Prints the original/encapsulated IP header + 64 bits of the
 *          original IP payload in an ICMP packet
 *
 * Arguments: log => pointer to TextLog
 *            p  => packet struct
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
static void LogICMPEmbeddedIP(TextLog* log, Packet *p)
{
    Packet op;
    Packet *orig_p;

    if (log == NULL || p == NULL)
        return;

    memset((char*)&op, 0, sizeof(op));
    orig_p = &op;

    if (!layer::set_api_ip_embed_icmp(p, op.ip_api))
    {
        switch(orig_p->ip_api.proto())
        {
            case IPPROTO_TCP:
            {
                const tcp::TCPHdr* tcph = layer::get_tcp_embed_icmp(op.ip_api);
                if (tcph)
                {
                    orig_p->sp = ntohs(tcph->th_sport);
                    orig_p->dp = ntohs(tcph->th_dport);
                    orig_p->tcph = tcph;
                }

                TextLog_Print(log, "\n** ORIGINAL DATAGRAM DUMP:\n");
                LogIPHeader(log, orig_p);

                if(tcph != NULL)
                {
                    TextLog_Print(log, "Seq: 0x%lX\n",
                            (u_long)ntohl(orig_p->tcph->th_seq));
                }
                break;
            }

            case IPPROTO_UDP:
            {
                const udp::UDPHdr* udph = layer::get_udp_embed_icmp(op.ip_api);
                if (udph)
                {
                    orig_p->sp = ntohs(p->udph->uh_sport);
                    orig_p->dp = ntohs(p->udph->uh_dport);
                    orig_p->udph = udph;
                }

                TextLog_Print(log, "\n** ORIGINAL DATAGRAM DUMP:\n");
                LogIPHeader(log, orig_p);

                if(udph != NULL)
                    TextLog_Print(log, "Len: %d  Csum: %d\n",
                            ntohs(orig_p->udph->uh_len) - udp::UDP_HEADER_LEN,
                            ntohs(orig_p->udph->uh_chk));
                break;
            }

            case IPPROTO_ICMP:
            {
                TextLog_Print(log, "\n** ORIGINAL DATAGRAM DUMP:\n");
                LogIPHeader(log, orig_p);

                const icmp::ICMPHdr* icmph = layer::get_icmp_embed_icmp(op.ip_api);
                if(icmph != NULL)
                    LogEmbeddedICMPHeader(log, icmph);
                break;
            }

            default:
                TextLog_Print(log, "\n** ORIGINAL DATAGRAM DUMP:\n");
                LogIPHeader(log, orig_p);

                TextLog_Print(log, "Protocol: 0x%X (unknown or "
                        "header truncated)", orig_p->ip_api.proto());
                break;
        }       /* switch */

        /* if more than 8 bytes of original IP payload sent */
        uint32_t orig_ip_hlen = p->ip_api.hlen() << 2;
        if (p->dsize - orig_ip_hlen > 8)
        {
            TextLog_Print(log, "(%d more bytes of original packet)\n",
                    p->dsize - orig_ip_hlen - 8);
        }

        TextLog_Puts(log, "** END OF DUMP");
    }
    else
    {
        TextLog_Puts(log, "\nORIGINAL DATAGRAM TRUNCATED");
    }
}

/*--------------------------------------------------------------------
 * Function: LogICMPHeader(TextLog* )
 *
 * Purpose: Print ICMP header
 *
 * Arguments: log => pointer to TextLog
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
void LogICMPHeader(TextLog*  log, Packet * p)
{
    /* 32 digits plus 7 colons and a NULL byte */
    char buf[8*4 + 7 + 1];

    if(p->icmph == NULL)
    {
        TextLog_Puts(log, "ICMP header truncated\n");
        return;
    }

    TextLog_Print(log, "Type:%d  Code:%d  ", p->icmph->type, p->icmph->code);

    switch(p->icmph->type)
    {
        case ICMP_ECHOREPLY:
            TextLog_Print(log, "ID:%d  Seq:%d  ", ntohs(p->icmph->s_icmp_id),
                    ntohs(p->icmph->s_icmp_seq));
            TextLog_Puts(log, "ECHO REPLY");
            break;

        case ICMP_DEST_UNREACH:
            TextLog_Puts(log, "DESTINATION UNREACHABLE: ");
            switch(p->icmph->code)
            {
                case ICMP_NET_UNREACH:
                    TextLog_Puts(log, "NET UNREACHABLE");
                    break;

                case ICMP_HOST_UNREACH:
                    TextLog_Puts(log, "HOST UNREACHABLE");
                    break;

                case ICMP_PROT_UNREACH:
                    TextLog_Puts(log, "PROTOCOL UNREACHABLE");
                    break;

                case ICMP_PORT_UNREACH:
                    TextLog_Puts(log, "PORT UNREACHABLE");
                    break;

                case ICMP_FRAG_NEEDED:
                    TextLog_Print(log, "FRAGMENTATION NEEDED, DF SET\n"
                            "NEXT LINK MTU: %u",
                            ntohs(p->icmph->s_icmp_nextmtu));
                    break;

                case ICMP_SR_FAILED:
                    TextLog_Puts(log, "SOURCE ROUTE FAILED");
                    break;

                case ICMP_NET_UNKNOWN:
                    TextLog_Puts(log, "NET UNKNOWN");
                    break;

                case ICMP_HOST_UNKNOWN:
                    TextLog_Puts(log, "HOST UNKNOWN");
                    break;

                case ICMP_HOST_ISOLATED:
                    TextLog_Puts(log, "HOST ISOLATED");
                    break;

                case ICMP_PKT_FILTERED_NET:
                    TextLog_Puts(log, "ADMINISTRATIVELY PROHIBITED NETWORK FILTERED");
                    break;

                case ICMP_PKT_FILTERED_HOST:
                    TextLog_Puts(log, "ADMINISTRATIVELY PROHIBITED HOST FILTERED");
                    break;

                case ICMP_NET_UNR_TOS:
                    TextLog_Puts(log, "NET UNREACHABLE FOR TOS");
                    break;

                case ICMP_HOST_UNR_TOS:
                    TextLog_Puts(log, "HOST UNREACHABLE FOR TOS");
                    break;

                case ICMP_PKT_FILTERED:
                    TextLog_Puts(log, "ADMINISTRATIVELY PROHIBITED,\nPACKET FILTERED");
                    break;

                case ICMP_PREC_VIOLATION:
                    TextLog_Puts(log, "PREC VIOLATION");
                    break;

                case ICMP_PREC_CUTOFF:
                    TextLog_Puts(log, "PREC CUTOFF");
                    break;

                default:
                    TextLog_Puts(log, "UNKNOWN");
                    break;

            }


            LogICMPEmbeddedIP(log, p);

            break;

        case ICMP_SOURCE_QUENCH:
            TextLog_Puts(log, "SOURCE QUENCH");

            LogICMPEmbeddedIP(log, p);

            break;

        case ICMP_REDIRECT:
            TextLog_Puts(log, "REDIRECT");
            switch(p->icmph->code)
            {
                case ICMP_REDIR_NET:
                    TextLog_Puts(log, " NET");
                    break;

                case ICMP_REDIR_HOST:
                    TextLog_Puts(log, " HOST");
                    break;

                case ICMP_REDIR_TOS_NET:
                    TextLog_Puts(log, " TOS NET");
                    break;

                case ICMP_REDIR_TOS_HOST:
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
            sfip_raw_ntop(AF_INET, (const void *)(&p->icmph->s_icmp_gwaddr.s_addr),
                          buf, sizeof(buf));
            TextLog_Print(log, " NEW GW: %s", buf);

            LogICMPEmbeddedIP(log, p);

            break;

        case ICMP_ECHO:
            TextLog_Print(log, "ID:%d   Seq:%d  ", ntohs(p->icmph->s_icmp_id),
                    ntohs(p->icmph->s_icmp_seq));
            TextLog_Puts(log, "ECHO");
            break;

        case ICMP_ROUTER_ADVERTISE:
            TextLog_Print(log, "ROUTER ADVERTISMENT: "
                    "Num addrs: %d Addr entry size: %d Lifetime: %u",
                    p->icmph->s_icmp_num_addrs, p->icmph->s_icmp_wpa,
                    ntohs(p->icmph->s_icmp_lifetime));
            break;

        case ICMP_ROUTER_SOLICIT:
            TextLog_Puts(log, "ROUTER SOLICITATION");
            break;

        case ICMP_TIME_EXCEEDED:
            TextLog_Puts(log, "TTL EXCEEDED");
            switch(p->icmph->code)
            {
                case ICMP_TIMEOUT_TRANSIT:
                    TextLog_Puts(log, " IN TRANSIT");
                    break;

                case ICMP_TIMEOUT_REASSY:
                    TextLog_Puts(log, " TIME EXCEEDED IN FRAG REASSEMBLY");
                    break;

                default:
                    break;
            }

            LogICMPEmbeddedIP(log, p);

            break;

        case ICMP_PARAMETERPROB:
            TextLog_Puts(log, "PARAMETER PROBLEM");
            switch(p->icmph->code)
            {
                case ICMP_PARAM_BADIPHDR:
                    TextLog_Print(log, ": BAD IP HEADER BYTE %u",
                            p->icmph->s_icmp_pptr);
                    break;

                case ICMP_PARAM_OPTMISSING:
                    TextLog_Puts(log, ": OPTION MISSING");
                    break;

                case ICMP_PARAM_BAD_LENGTH:
                    TextLog_Puts(log, ": BAD LENGTH");
                    break;

                default:
                    break;
            }

            LogICMPEmbeddedIP(log, p);

            break;

        case ICMP_TIMESTAMP:
            TextLog_Print(log, "ID: %u  Seq: %u  TIMESTAMP REQUEST",
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
            break;

        case ICMP_TIMESTAMPREPLY:
            TextLog_Print(log, "ID: %u  Seq: %u  TIMESTAMP REPLY:\n"
                    "Orig: %u Rtime: %u  Ttime: %u",
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq),
                    p->icmph->s_icmp_otime, p->icmph->s_icmp_rtime,
                    p->icmph->s_icmp_ttime);
            break;

        case ICMP_INFO_REQUEST:
            TextLog_Print(log, "ID: %u  Seq: %u  INFO REQUEST",
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
            break;

        case ICMP_INFO_REPLY:
            TextLog_Print(log, "ID: %u  Seq: %u  INFO REPLY",
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
            break;

        case ICMP_ADDRESS:
            TextLog_Print(log, "ID: %u  Seq: %u  ADDRESS REQUEST",
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
            break;

        case ICMP_ADDRESSREPLY:
            TextLog_Print(log, "ID: %u  Seq: %u  ADDRESS REPLY: 0x%08X",
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq),
                    (u_int) ntohl(p->icmph->s_icmp_mask));
            break;

        default:
            TextLog_Puts(log, "UNKNOWN");

            break;
    }

    TextLog_NewLine(log);

}

/*--------------------------------------------------------------------
 * reference stuff cloned from signature.c
 *--------------------------------------------------------------------
 */
/* print a reference node */
static void LogReference(TextLog* log, ReferenceNode *refNode)
{
    if(refNode)
    {
        if(refNode->system)
        {
            if(refNode->system->url)
                TextLog_Print(log, "[Xref => %s%s]", refNode->system->url,
                        refNode->id);
            else
                TextLog_Print(log, "[Xref => %s %s]", refNode->system->name,
                        refNode->id);
        }
        else
        {
            TextLog_Print(log, "[Xref => %s]", refNode->id);
        }
    }
    return;
}

/*
 * Function: LogXrefs(TextLog* )
 *
 * Purpose: Prints out cross reference data associated with an alert
 *
 * Arguments: log => pointer to TextLog to write the data to
 *            doNewLine => tack a \n to the end of the line or not (bool)
 *
 * Returns: void function
 */
void LogXrefs(TextLog* log, const Event* e, bool doNewLine)
{
    ReferenceNode* refNode = e->sig_info->refs;

    while ( refNode )
    {
        LogReference(log, refNode);
        refNode = refNode->next;

        /* on the last loop through, print a newline in
           Full mode */
        if(doNewLine && (refNode == NULL))
            TextLog_NewLine(log);
    }
}

/*--------------------------------------------------------------------
 * payload stuff cloned from log.c
 *--------------------------------------------------------------------
 */
/*--------------------------------------------------------------------
 * Function: ScOutputCharData(TextLog*, char*, int)
 *
 * Purpose: Dump the printable ASCII data from a packet
 *
 * Arguments: log => ptr to TextLog to print to
 *            data => pointer to buffer data
 *            len => length of data buffer
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */
static void LogCharData(TextLog* log, char *data, int len)
{
    const char* pb = data;
    const char* end = data + len;
    int lineCount = 0;

    if ( !data )
    {
        return;
    }

    while ( pb < end )
    {
        if ( *pb > 0x1F && *pb < 0x7F)
        {   /* printable */
            TextLog_Putc(log, *pb);
        }
        else
        {   /* not printable */
            TextLog_Putc(log, '.');
        }

        if ( ++lineCount == 64 )
        {
            TextLog_Putc(log, ' ');
            TextLog_NewLine(log);
            lineCount = 0;
        }
        pb++;
    }
    /* slam a \n on the back */
    TextLog_Putc(log, ' ');
    TextLog_NewLine(log);
    TextLog_Putc(log, ' ');
}

/*
 * Function: LogNetData(TextLog*, uint8_t *,int, Packet *)
 *
 * Purpose: Do a side by side dump of a buffer, hex on
 *          the left, decoded ASCII on the right.
 *
 * Arguments: log => ptr to TextLog to print to
 *            data => pointer to buffer data
 *            len => length of data buffer
 *
 * Returns: void function
 */
#define BYTES_PER_FRAME 16
/* middle of packet:"41 02 43 04 45 06 47 08 49 0A 4B 0C 4D 0E 4F 0F  A.C.E.G.I.K.M.O."*/
/* at end of packet:"41 02 43 04 45 06 47 08                          A.C.E.G."*/
static const char* pad3 = "                                                 ";

void LogNetData (TextLog* log, const uint8_t* data, const int len, Packet *p)
{
    const uint8_t* pb = data;
    const uint8_t* end = data + len;

    int offset = 0;
    char conv[] = "0123456789ABCDEF";   /* xlation lookup table */
    int ip_ob_start, ip_ob_end, byte_pos, char_pos;
    int i;

    byte_pos = char_pos = 0;

    ip_ob_start = ip_ob_end = -1;

    if ( !len )
    {
        TextLog_NewLine(log);
        return;
    }
    if ( !data )
    {
        TextLog_Print(log, "Got NULL ptr in LogNetData()\n");
        return;
    }

    if ( len > IP_MAXPACKET )
    {
        if (ScLogVerbose())
        {
            TextLog_Print(
                log, "Got bogus buffer length (%d) for LogNetData, "
                "defaulting to %d bytes!\n", len, BYTES_PER_FRAME
            );
        }
        end = data + BYTES_PER_FRAME;
    }

    if(p && ScObfuscate() )
    {
        int num_layers =  p->num_layers;
        for ( i = 0; i < num_layers; i++ )
        {
            if ( p->layers[i].proto == PROTO_IP4
                  || p->layers[i].proto == PROTO_IP6
                )
            {
                if(p->layers[i].length && p->layers[i].start)
                break;
            }
        }

        int ip_start = p->layers[i].start - data;

        if(ip_start > 0 )
        {
            ip_ob_start = ip_start + 10;
            if(p->layers[i].proto == PROTO_IP4)
                ip_ob_end = ip_ob_start + 2 + 2*(sizeof(struct in_addr));
            else
                ip_ob_end = ip_ob_start + 2 + 2*(sizeof(struct in6_addr));

        }

    }

    /* loop thru the whole buffer */
    while ( pb < end )
    {
        if (ScVerboseByteDump())
        {
            TextLog_Print(log, "0x%04X: ", offset);
            offset += BYTES_PER_FRAME;
        }
        /* process one frame */
        /* first print the binary as ascii hex */
        for (i = 0; i < BYTES_PER_FRAME && pb+i < end; i++, byte_pos++)
        {
            if(ScObfuscate() && ((byte_pos >= ip_ob_start) && (byte_pos < ip_ob_end)))
            {
                TextLog_Putc(log, 'X');
                TextLog_Putc(log, 'X');
                TextLog_Putc(log, ' ');
            }
            else
            {
                char b = pb[i];
                TextLog_Putc(log, conv[(b & 0xFF) >> 4]);
                TextLog_Putc(log, conv[(b & 0xFF) & 0x0F]);
                TextLog_Putc(log, ' ');
            }
        }
        /* print ' ' past end of packet and before ascii */
        TextLog_Puts(log, pad3+(3*i));

        /* then print the actual ascii chars */
        /* or a '.' for control chars */
        for (i = 0; i < BYTES_PER_FRAME && pb+i < end; i++, char_pos++)
        {
            if(ScObfuscate() && ((char_pos >= ip_ob_start) && (char_pos < ip_ob_end)))
            {
                TextLog_Putc(log, 'X');
            }
            else
            {
                char b = pb[i];

                if ( b > 0x1F && b < 0x7F)
                    TextLog_Putc(log, (char)(b & 0xFF));
                else
                    TextLog_Putc(log, '.');
            }
        }
        pb += BYTES_PER_FRAME;
        TextLog_NewLine(log);
    }
    TextLog_NewLine(log);
}

#define SEPARATOR \
    "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="

static int LogObfuscatedData(TextLog* log, Packet *p)
{
    uint8_t *payload = NULL;
    uint16_t payload_len = 0;

    TextLog_Print(log, "%s\n", SEPARATOR);

    if (obApi->getObfuscatedPayload(p, &payload,
                (uint16_t *)&payload_len) != OB_RET_SUCCESS)
    {
        return -1;
    }

    /* dump the application layer data */
    if (ScOutputAppData() && !ScVerboseByteDump())
    {
        if (ScOutputCharData())
            LogCharData(log, (char *)payload, payload_len);
        else
            LogNetData(log, payload, payload_len, NULL);
    }
    else if (ScVerboseByteDump())
    {
        uint8_t buf[UINT16_MAX];
        uint16_t dlen = p->data - p->pkt;

        SafeMemcpy(buf, p->pkt, dlen, buf, buf + sizeof(buf));
        SafeMemcpy(buf + dlen, payload, payload_len,
                buf, buf + sizeof(buf));

        LogNetData(log, buf, dlen + payload_len, NULL);
    }

    free(payload);

    return 0;
}

static void LogPacketType(TextLog* log, Packet* p)
{
    TextLog_NewLine(log);

    if ( !p->dsize || !PacketWasCooked(p) )
        return;

    switch ( p->pseudo_type ) {
    case PSEUDO_PKT_SMB_SEG:
        TextLog_Print(log, "%s", "SMB desegmented packet");
        break;
    case PSEUDO_PKT_DCE_SEG:
        TextLog_Print(log, "%s", "DCE/RPC desegmented packet");
        break;
    case PSEUDO_PKT_DCE_FRAG:
        TextLog_Print(log, "%s", "DCE/RPC defragmented packet");
        break;
    case PSEUDO_PKT_SMB_TRANS:
        TextLog_Print(log, "%s", "SMB Transact reassembled packet");
        break;
    case PSEUDO_PKT_DCE_RPKT:
        TextLog_Print(log, "%s", "DCE/RPC reassembled packet");
        break;
    case PSEUDO_PKT_TCP:
        TextLog_Print(log, "%s", "Stream reassembled packet");
        break;
    case PSEUDO_PKT_IP:
        TextLog_Print(log, "%s", "Frag reassembled packet");
        break;
    default:
        // FIXIT-L do we get here for portscan or sdf?
        TextLog_Print(log, "%s", "Cooked packet");
        break;
    }
    TextLog_NewLine(log);
}

/*--------------------------------------------------------------------
 * Function: LogIPPkt(TextLog*, int, Packet *)
 *
 * Purpose: Dump the packet to the given TextLog
 *
 * Arguments: log => pointer to print data to
 *            type => packet protocol
 *            p => pointer to decoded packet struct
 *
 * Returns: void function
 *--------------------------------------------------------------------
 */

#define DATA_LEN(p) \
    (p->ip_api.actual_ip_len() - (p->ip_api.hlen() << 2))

void LogIPPkt(TextLog* log, int type, Packet * p)
{
#ifdef DEBUG_MSGS
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "LogIPPkt type = %d\n", type););
#else
    UNUSED(type);
#endif
    LogPacketType(log, p);
    TextLog_Print(log, "%s\n", SEPARATOR);

    /* dump the timestamp */
    LogTimeStamp(log, p);

    /* dump the ethernet header if we're doing that sort of thing */
    if ( ScOutputDataLink() )
    {
        Log2ndHeader(log, p);

        if ( p->proto_bits & PROTO_BIT__MPLS )
        {
            LogMPLSHeader(log, p);
        }


        // FIXIT-J --> log everything in order!!
        ip::IpApi tmp_api = p->ip_api;
        int8_t num_layer = 0;
        bool first = true;

        while (layer::set_outer_ip_api(p, p->ip_api, num_layer) &&
            tmp_api != p->ip_api)
        {
            LogOuterIPHeader(log, p);

            if (first)
                LogGREHeader(log, p); // checks for valid gre layer before logging
            else
                first = false;

        }

        p->ip_api = tmp_api;
    }

    LogIPHeader(log, p);

    /* if this isn't a fragment, print the other header info */
    if (!(p->decode_flags & DECODE__FRAG))
    {
        switch (p->ip_api.proto())
        {
            case IPPROTO_TCP:
                if ( p->tcph != NULL )
                {
                    LogTCPHeader(log, p);
                }
                else
                {
                    LogNetData(log, p->ip_api.ip_data(), p->ip_api.pay_len(), NULL);
                }
                break;

            case IPPROTO_UDP:
                if ( p->udph != NULL )
                {
                    // for consistency, nothing to log (tcp doesn't log paylen)
                    //LogUDPHeader(log, p);
                }
                else
                {
                    LogNetData(log, p->ip_api.ip_data(), p->ip_api.pay_len(), NULL);
                }

                break;

            case IPPROTO_ICMP:
                if ( p->icmph != NULL )
                {
                    LogICMPHeader(log, p);
                }
                else
                {
                    LogNetData(log, p->ip_api.ip_data(), p->ip_api.pay_len(), NULL);
                }
                break;

            default:
                break;
        }
    }

    if ((p->dsize > 0) && obApi->payloadObfuscationRequired(p)
            && (LogObfuscatedData(log, p) == 0))
    {
        return;
    }

    /* dump the application layer data */
    if (ScOutputAppData() && !ScVerboseByteDump())
    {
        if (ScOutputCharData())
        {
            LogCharData(log, (char *)p->data, p->dsize);
            if(!IsJSNormData(p->flow))
            {
                TextLog_Print(log, "%s\n", "Normalized JavaScript for this packet");
                LogCharData(log, (char *)g_file_data.data, g_file_data.len);
            }
            else if(!IsGzipData(p->flow))
            {
                TextLog_Print(log, "%s\n", "Decompressed Data for this packet");
                LogCharData(log, (char *)g_file_data.data, g_file_data.len);
            }
        }
        else
        {
            LogNetData(log, p->data, p->dsize, NULL);
            if(!IsJSNormData(p->flow))
            {
                TextLog_Print(log, "%s\n", "Normalized JavaScript for this packet");
                LogNetData(log, g_file_data.data, g_file_data.len, NULL);
            }
            else if(!IsGzipData(p->flow))
            {
                TextLog_Print(log, "%s\n", "Decompressed Data for this packet");
                LogNetData(log, g_file_data.data, g_file_data.len, NULL);
            }
        }
    }
    else if (ScVerboseByteDump())
    {
        LogNetData(log, p->pkt, p->pkth->caplen, p);
    }
}

/*--------------------------------------------------------------------
 * ARP stuff cloned from log.c
 *--------------------------------------------------------------------
 */
void LogArpHeader(TextLog*, Packet*)
{
// XXX-IPv6 "NOT YET IMPLEMENTED - printing ARP header"
}


#if 0
// these must be converted to use TextLog 
// (or just deleted)
/****************************************************************************
 *
 * Function: PrintEapolKey(FILE *)
 *
 * Purpose: Dump the EAP header to the specified file stream
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
static void PrintEapolKey(FILE * fp,  const eapol::EapolKey* eapolk)
{

    uint16_t length;

    if(eapolk == NULL)
    {
        fprintf(fp, "Eapol Key truncated\n");
        return;
    }
    fprintf(fp, "KEY type: ");
    if (eapolk->type == 1) {
      fprintf(fp, "RC4");
    }

    memcpy(&length, &eapolk->length, 2);
    length = ntohs(length);
    fprintf(fp, " len: %d", length);
    fprintf(fp, " index: %d ", eapolk->index & 0x7F);
    fprintf(fp, eapolk->index & 0x80 ? " unicast\n" : " broadcast\n");
}

/****************************************************************************
 *
 * Function: PrintEapolHeader(FILE *, Packet *)
 *
 * Purpose: Dump the EAPOL header info to the specified stream
 *
 * Arguments: fp => stream to print to
 *
 * Returns: void function
 *
 ***************************************************************************/
static void PrintEapolHeader(FILE * fp, const eapol::EtherEapol* eplh)
{
    fprintf(fp, "EAPOL type: ");
    switch(eplh->eaptype) {
    case EAPOL_TYPE_EAP:
        fprintf(fp, "EAP");
        break;
    case EAPOL_TYPE_START:
        fprintf(fp, "Start");
        break;
    case EAPOL_TYPE_LOGOFF:
        fprintf(fp, "Logoff");
        break;
    case EAPOL_TYPE_KEY:
        fprintf(fp, "Key");
        break;
    case EAPOL_TYPE_ASF:
        fprintf(fp, "ASF Alert");
        break;
    default:
        fprintf(fp, "Unknown");
    }
    fprintf(fp, " Len: %d\n", ntohs(eplh->len));
}

/****************************************************************************
 *
 * Function: PrintEAPHeader(FILE *)
 *
 * Purpose: Dump the EAP header to the specified file stream
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
static void PrintEAPHeader(FILE * fp, const eapol::EAPHdr* eaph)
{
    uint8_t* eaptype = 0;

    if(eaph == NULL)
    {
        fprintf(fp, "EAP header truncated\n");
        return;
    }
    fprintf(fp, "code: ");
    switch(eaph->code) {
    case EAP_CODE_REQUEST:
        fprintf(fp, "Req ");
        eaptype = (uint8_t*) (eaph + sizeof(*eaph));
        break;
    case EAP_CODE_RESPONSE:
        fprintf(fp, "Resp");
        eaptype = (uint8_t*) (eaph + sizeof(*eaph));
        break;
    case EAP_CODE_SUCCESS:
        fprintf(fp, "Succ");
        break;
    case EAP_CODE_FAILURE:
        fprintf(fp, "Fail");
        break;
    }
    fprintf(fp, " id: 0x%x len: %d", eaph->id, ntohs(eaph->len));
    if (eaptype != NULL)
    {
        fprintf(fp, " type: ");
        switch(*(eaptype))
        {
            case EAP_TYPE_IDENTITY:
            fprintf(fp, "id");
            break;
              case EAP_TYPE_NOTIFY:
            fprintf(fp, "notify");
            break;
              case EAP_TYPE_NAK:
            fprintf(fp, "nak");
            break;
              case EAP_TYPE_MD5:
            fprintf(fp, "md5");
            break;
              case EAP_TYPE_OTP:
            fprintf(fp, "otp");
            break;
              case EAP_TYPE_GTC:
            fprintf(fp, "token");
            break;
              case EAP_TYPE_TLS:
            fprintf(fp, "tls");
            break;
              default:
            fprintf(fp, "undef");
            break;
        }
    }
    fprintf(fp, "\n");
}
/*
 * Function: PrintEapolPkt(FILE *, Packet *)
 *
 * Purpose: Dump the packet to the stream pointer
 *
 * Arguments: fp => pointer to print data to
 *            type => packet protocol
 *            p => pointer to decoded packet struct
 *
 * Returns: void function
 */
void PrintEapolPkt(FILE * fp, Packet * p)
{
  char timestamp[TIMEBUF_SIZE];


    memset((char *) timestamp, 0, TIMEBUF_SIZE);
    ts_print((struct timeval *) & p->pkth->ts, timestamp);

    /* dump the timestamp */
    fwrite(timestamp, strlen(timestamp), 1, fp);

    /* dump the ethernet header if we're doing that sort of thing */
    if (ScOutputDataLink())
    {
        Print2ndHeader(fp, p);
    }

    const eapol::EtherEapol* eplh = layer::get_eapol_layer(p);

    if (eplh)
    {
        PrintEapolHeader(fp, eplh);
        if (eplh->eaptype == EAPOL_TYPE_EAP) {
            PrintEAPHeader(fp, (const eapol::EAPHdr*) eplh + sizeof(*eplh));
        }
        else if (eplh->eaptype == EAPOL_TYPE_KEY) {
            PrintEapolKey(fp, (const eapol::EapolKey*) eplh + sizeof(*eplh));
        }
    }
    else
    {
        fprintf(fp, "EAP header truncated\n");
    }

    /* dump the application layer data */
    if(ScOutputAppData() && !ScVerboseByteDump())
    {
        if (ScOutputCharData())
            PrintCharData(fp, (char*) p->data, p->dsize);
        else
            PrintNetData(fp, p->data, p->dsize, NULL);
    }
    else if (ScVerboseByteDump())
    {
        PrintNetData(fp, p->pkt, p->pkth->caplen, p);
    }

    fprintf(fp, "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");
}

/*
 * Function: PrintWifiPkt(FILE *, Packet *)
 *
 * Purpose: Dump the packet to the stream pointer
 *
 * Arguments: fp => pointer to print data to
 *            p => pointer to decoded packet struct
 *
 * Returns: void function
 */
void PrintWifiPkt(FILE * fp, Packet * p)
{
    char timestamp[TIMEBUF_SIZE];


    memset((char *) timestamp, 0, TIMEBUF_SIZE);
    ts_print((struct timeval *) & p->pkth->ts, timestamp);

    /* dump the timestamp */
    fwrite(timestamp, strlen(timestamp), 1, fp);

    /* dump the ethernet header if we're doing that sort of thing */
    Print2ndHeader(fp, p);

    /* dump the application layer data */
    if (ScOutputAppData() && !ScVerboseByteDump())
    {
        if (ScOutputCharData())
            PrintCharData(fp, (char*) p->data, p->dsize);
        else
            PrintNetData(fp, p->data, p->dsize, NULL);
    }
    else if (ScVerboseByteDump())
    {
        PrintNetData(fp, p->pkt, p->pkth->caplen, p);
    }

    fprintf(fp, "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+"
            "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");
}
#endif

