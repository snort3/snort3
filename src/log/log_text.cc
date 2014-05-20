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
#include "decode.h"
#include "snort.h"
#include "sf_textlog.h"
#include "snort_bounds.h"
#include "obfuscation.h"
#include "detection_util.h"
#include "packet_io/sfdaq.h"

#include "sfip/sf_ip.h"

#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/icmp6.h"
#include "protocols/icmp4.h"
#include "protocols/wlan.h"

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
#ifndef NO_NON_ETHER_DECODER
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

    TextLog_Print(log, "%X:%X:%X:%X:%X:%X -> ", p->trh->saddr[0],
            p->trh->saddr[1], p->trh->saddr[2], p->trh->saddr[3],
            p->trh->saddr[4], p->trh->saddr[5]);
    TextLog_Print(log, "%X:%X:%X:%X:%X:%X\n", p->trh->daddr[0],
            p->trh->daddr[1], p->trh->daddr[2], p->trh->daddr[3],
            p->trh->daddr[4], p->trh->daddr[5]);

    TextLog_Print(log, "access control:0x%X frame control:0x%X\n", p->trh->ac,
            p->trh->fc);
    if(!p->trhllc)
        return;
    TextLog_Print(log, "DSAP: 0x%X SSAP 0x%X protoID: %X%X%X Ethertype: %X\n",
            p->trhllc->dsap, p->trhllc->ssap, p->trhllc->protid[0],
            p->trhllc->protid[1], p->trhllc->protid[2], p->trhllc->ethertype);
    if(p->trhmr)
    {
        TextLog_Print(log, "RIF structure is present:\n");
        TextLog_Print(log, "bcast: 0x%X length: 0x%X direction: 0x%X largest"
                "fr. size: 0x%X res: 0x%X\n",
                TRH_MR_BCAST(p->trhmr), TRH_MR_LEN(p->trhmr),
        TRH_MR_DIR(p->trhmr), TRH_MR_LF(p->trhmr),
                TRH_MR_RES(p->trhmr));
        TextLog_Print(log, "rseg -> %X:%X:%X:%X:%X:%X:%X:%X\n",
                p->trhmr->rseg[0], p->trhmr->rseg[1], p->trhmr->rseg[2],
                p->trhmr->rseg[3], p->trhmr->rseg[4], p->trhmr->rseg[5],
                p->trhmr->rseg[6], p->trhmr->rseg[7]);
    }
}
#endif  // NO_NON_ETHER_DECODER

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
    /* src addr */
    TextLog_Print(log, "%02X:%02X:%02X:%02X:%02X:%02X -> ", p->eh->ether_src[0],
        p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
        p->eh->ether_src[4], p->eh->ether_src[5]);

    /* dest addr */
    TextLog_Print(log, "%02X:%02X:%02X:%02X:%02X:%02X ", p->eh->ether_dst[0],
        p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
        p->eh->ether_dst[4], p->eh->ether_dst[5]);

    /* protocol and pkt size */
    TextLog_Print(log, "type:0x%X len:0x%X\n", ntohs(p->eh->ether_type),
        p->pkth->pktlen);
}

static void LogMPLSHeader(TextLog* log, Packet* p)
{

    TextLog_Print(log,"label:0x%05X exp:0x%X bos:0x%X ttl:0x%X\n",
        p->mplsHdr.label, p->mplsHdr.exp, p->mplsHdr.bos, p->mplsHdr.ttl);
}

static void LogGREHeader(TextLog *log, Packet *p)
{
    if (p->greh == NULL)
        return;

    TextLog_Print(log, "GRE version:%u flags:0x%02X ether-type:0x%04X\n",
            GRE_VERSION(p->greh), p->greh->flags, GRE_PROTO(p->greh));
}

#ifndef NO_NON_ETHER_DECODER
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
    switch (ntohs(p->sllh->sll_pkttype)) {
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
        htons(p->sllh->sll_halen), ntohs(p->sllh->sll_hatype),
        p->sllh->sll_addr[0], p->sllh->sll_addr[1], p->sllh->sll_addr[2],
        p->sllh->sll_addr[3], p->sllh->sll_addr[4], p->sllh->sll_addr[5]);

    /* protocol and pkt size */
    TextLog_Print(log, "pkt type:0x%X proto: 0x%X len:0x%X\n",
        ntohs(p->sllh->sll_pkttype),
        ntohs(p->sllh->sll_protocol), p->pkth->pktlen);
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
  /* This assumes we are printing a data packet, could be changed
     to print other types as well */
  const uint8_t *da = NULL, *sa = NULL, *bssid = NULL, *ra = NULL,
    *ta = NULL;
  /* per table 4, IEEE802.11 section 7.2.2 */
  if ((p->wifih->frame_control & WLAN_FLAG_TODS) &&
      (p->wifih->frame_control & WLAN_FLAG_FROMDS)) {
    ra = p->wifih->addr1;
    ta = p->wifih->addr2;
    da = p->wifih->addr3;
    sa = p->wifih->addr4;
  }
  else if (p->wifih->frame_control & WLAN_FLAG_TODS) {
    bssid = p->wifih->addr1;
    sa = p->wifih->addr2;
    da = p->wifih->addr3;
  }
  else if (p->wifih->frame_control & WLAN_FLAG_FROMDS) {
    da = p->wifih->addr1;
    bssid = p->wifih->addr2;
    sa = p->wifih->addr3;
  }
  else {
    da = p->wifih->addr1;
    sa = p->wifih->addr2;
    bssid = p->wifih->addr3;
  }

  /* DO this switch to provide additional info on the type */
  switch(p->wifih->frame_control & 0x00ff)
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
  if (p->wifih->frame_control & WLAN_FLAG_TODS)    TextLog_Puts(log," ToDs");
  if (p->wifih->frame_control & WLAN_FLAG_TODS)    TextLog_Puts(log," FrDs");
  if (p->wifih->frame_control & WLAN_FLAG_FRAG)    TextLog_Puts(log," Frag");
  if (p->wifih->frame_control & WLAN_FLAG_RETRY)   TextLog_Puts(log," Re");
  if (p->wifih->frame_control & WLAN_FLAG_PWRMGMT) TextLog_Puts(log," Pwr");
  if (p->wifih->frame_control & WLAN_FLAG_MOREDAT) TextLog_Puts(log," MD");
  if (p->wifih->frame_control & WLAN_FLAG_WEP)     TextLog_Puts(log," Wep");
  if (p->wifih->frame_control & WLAN_FLAG_ORDER)   TextLog_Puts(log," Ord");
  TextLog_NewLine(log);
}
#endif  // NO_NON_ETHER_DECODER

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
            if(p && p->eh)
                LogEthHeader(log, p);
            break;
#ifndef NO_NON_ETHER_DECODER
#ifdef DLT_IEEE802_11
        case DLT_IEEE802_11:
            if(p && p->wifih)
                LogWifiHeader(log, p);
            break;
#endif
        case DLT_IEEE802:                /* Token Ring */
            if(p && p->trh)
                LogTrHeader(log, p);
            break;
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            if (p && p->sllh)
                LogSLLHeader(log, p);  /* Linux cooked sockets */
            break;
#endif
#endif  // NO_NON_ETHER_DECODER
        default:
            if (ScLogVerbose())
            {
                // FIXTHIS should only be output once!
                ErrorMessage("Datalink %i type 2nd layer display is not "
                             "supported\n", DAQ_GetBaseProtocol());
            }
    }
}

/*-------------------------------------------------------------------
 * IP stuff cloned from log.c
 *-------------------------------------------------------------------
 */
static void LogIpOptions(TextLog*  log, Packet * p)
{
    int i;
    int j;
    u_long init_offset;
    u_long print_offset;

    init_offset = TextLog_Tell(log);

    if(!p->ip_option_count || p->ip_option_count > 40)
        return;

    TextLog_Print(log, "IP Options (%d) => ", p->ip_option_count);

    for(i = 0; i < (int) p->ip_option_count; i++)
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

                if(p->ip_options[i].len)
                {
                    for(j = 0; j < p->ip_options[i].len; j++)
                    {
                        if (p->ip_options[i].data)
                            TextLog_Print(log, "%02X", p->ip_options[i].data[j]);
                        else
                            TextLog_Print(log, "%02X", 0);

                        if((j % 2) == 0)
                            TextLog_Putc(log, ' ');
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
    if (!IPH_IS_VALID(p))
        return;

    if (p->frag_flag
            || ((GET_IPH_PROTO(p) != IPPROTO_TCP)
                && (GET_IPH_PROTO(p) != IPPROTO_UDP)))
    {
        const char *ip_fmt = "%s -> %s";

        if (ScObfuscate())
        {
            TextLog_Print(log, ip_fmt,
                    ObfuscateIpToText(GET_SRC_ADDR(p)),
                    ObfuscateIpToText(GET_DST_ADDR(p)));
        }
        else
        {
            TextLog_Print(log, ip_fmt,
                    inet_ntoax(GET_SRC_ADDR(p)),
                    inet_ntoax(GET_DST_ADDR(p)));
        }
    }
    else
    {
        const char *ip_fmt = "%s:%d -> %s:%d";

        if (ScObfuscate())
        {
            TextLog_Print(log, ip_fmt,
                    ObfuscateIpToText(GET_SRC_ADDR(p)), p->sp,
                    ObfuscateIpToText(GET_DST_ADDR(p)), p->dp);
        }
        else
        {
            TextLog_Print(log, ip_fmt,
                    inet_ntoax(GET_SRC_ADDR(p)), p->sp,
                    inet_ntoax(GET_DST_ADDR(p)), p->dp);
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
    if(!IPH_IS_VALID(p))
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
            protocol_names[GET_IPH_PROTO(p)],
            GET_IPH_TTL(p),
            GET_IPH_TOS(p),
            IS_IP6(p) ? ntohl(GET_IPH_ID(p)) : ntohs((uint16_t)GET_IPH_ID(p)),
            GET_IPH_HLEN(p) << 2,
            GET_IP_DGMLEN(p));

    /* print the reserved bit if it's set */
    if((uint8_t)((ntohs(GET_IPH_OFF(p)) & 0x8000) >> 15) == 1)
        TextLog_Puts(log, " RB");

    /* printf more frags/don't frag bits */
    if((uint8_t)((ntohs(GET_IPH_OFF(p)) & 0x4000) >> 14) == 1)
        TextLog_Puts(log, " DF");

    if((uint8_t)((ntohs(GET_IPH_OFF(p)) & 0x2000) >> 13) == 1)
        TextLog_Puts(log, " MF");

    TextLog_NewLine(log);

    /* print IP options */
    if(p->ip_option_count != 0)
    {
        LogIpOptions(log, p);
    }

    /* print fragment info if necessary */
    if(p->frag_flag)
    {
        TextLog_Print(log, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
                (p->frag_offset & 0x1FFF),
                GET_IP_PAYLEN(p));
    }
}

static void LogOuterIPHeader(TextLog *log, Packet *p)
{
    int save_family = p->family;
    IPH_API *save_api = p->iph_api;
    const IPHdr *save_iph = p->iph;
    uint8_t save_ip_option_count = p->ip_option_count;
    IP4Hdr *save_ip4h = p->ip4h;
    IP6Hdr *save_ip6h = p->ip6h;
    uint8_t save_frag_flag = p->frag_flag;
    uint16_t save_sp, save_dp;

    p->family = p->outer_family;
    p->iph_api = p->outer_iph_api;
    p->iph = p->outer_iph;
    p->ip_option_count = 0;
    p->ip4h = &p->outer_ip4h;
    p->ip6h = &p->outer_ip6h;
    p->frag_flag = 0;

    if (p->proto_bits & PROTO_BIT__TEREDO)
    {
        save_sp = p->sp;
        save_dp = p->dp;

        if (p->outer_udph)
        {
            p->sp = ntohs(p->outer_udph->uh_sport);
            p->dp = ntohs(p->outer_udph->uh_dport);
        }
        else
        {
            p->sp = ntohs(p->udph->uh_sport);
            p->dp = ntohs(p->udph->uh_dport);
        }
        LogIPHeader(log, p);

        p->sp = save_sp;
        p->dp = save_dp;
    }
    else
        LogIPHeader(log, p);

    p->family = save_family;
    p->iph_api = save_api;
    p->iph = save_iph;
    p->ip_option_count = save_ip_option_count;
    p->ip4h = save_ip4h;
    p->ip6h = save_ip6h;
    p->frag_flag = save_frag_flag;
}

/*-------------------------------------------------------------------
 * TCP stuff cloned from log.c
 *-------------------------------------------------------------------
 */
static void LogTcpOptions(TextLog*  log, Packet * p)
{
    int i;
    int j;
    uint8_t tmp[5];
#if 0
    u_long init_offset;
    u_long print_offset;

    init_offset = TextLog_Tell(log);
#endif

    TextLog_Print(log, "TCP Options (%d) => ", p->tcp_option_count);

    if(p->tcp_option_count > 40 || !p->tcp_option_count)
        return;

    for(i = 0; i < (int) p->tcp_option_count; i++)
    {
#if 0
        print_offset = TextLog_Tell(log);

        if((print_offset - init_offset) > 60)
        {
            TextLog_Puts(log, "\nTCP Options => ");
            init_offset = TextLog_Tell(log);
        }
#endif
        switch(p->tcp_options[i].code)
        {
            case TCPOPT_MAXSEG:
                memset((char*)tmp, 0, sizeof(tmp));
                TextLog_Puts(log, "MSS: ");
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 2);
                TextLog_Print(log, "%u ", EXTRACT_16BITS(tmp));
                break;

            case TCPOPT_EOL:
                TextLog_Puts(log, "EOL ");
                break;

            case TCPOPT_NOP:
                TextLog_Puts(log, "NOP ");
                break;

            case TCPOPT_WSCALE:
                if (p->tcp_options[i].data)
                    TextLog_Print(log, "WS: %u ", p->tcp_options[i].data[0]);
                else
                    TextLog_Print(log, "WS: %u ", 0);
                break;
            case TCPOPT_SACK:
                memset((char*)tmp, 0, sizeof(tmp));
                if (p->tcp_options[i].data && (p->tcp_options[i].len >= 2))
                    memcpy(tmp, p->tcp_options[i].data, 2);
                TextLog_Print(log, "Sack: %u@", EXTRACT_16BITS(tmp));
                memset((char*)tmp, 0, sizeof(tmp));
                if (p->tcp_options[i].data && (p->tcp_options[i].len >= 4))
                    memcpy(tmp, (p->tcp_options[i].data) + 2, 2);
                TextLog_Print(log, "%u ", EXTRACT_16BITS(tmp));
                break;

            case TCPOPT_SACKOK:
                TextLog_Puts(log, "SackOK ");
                break;

            case TCPOPT_ECHO:
                memset((char*)tmp, 0, sizeof(tmp));
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                TextLog_Print(log, "Echo: %u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_ECHOREPLY:
                memset((char*)tmp, 0, sizeof(tmp));
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                TextLog_Print(log, "Echo Rep: %u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_TIMESTAMP:
                memset((char*)tmp, 0, sizeof(tmp));
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                TextLog_Print(log, "TS: %u ", EXTRACT_32BITS(tmp));
                memset((char*)tmp, 0, sizeof(tmp));
                if (p->tcp_options[i].data)
                    memcpy(tmp, (p->tcp_options[i].data) + 4, 4);
                TextLog_Print(log, "%u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_CC:
                memset((char*)tmp, 0, sizeof(tmp));
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                TextLog_Print(log, "CC %u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_CC_NEW:
                memset((char*)tmp, 0, sizeof(tmp));
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                TextLog_Print(log, "CCNEW: %u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_CC_ECHO:
                memset((char*)tmp, 0, sizeof(tmp));
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                TextLog_Print(log, "CCECHO: %u ", EXTRACT_32BITS(tmp));
                break;

            default:
                if(p->tcp_options[i].len)
                {
                    TextLog_Print(log, "Opt %d (%d): ", p->tcp_options[i].code,
                            (int) p->tcp_options[i].len);

                    for(j = 0; j < p->tcp_options[i].len; j++)
                    {
                        if (p->tcp_options[i].data)
                            TextLog_Print(log, "%02X", p->tcp_options[i].data[j]);
                        else
                            TextLog_Print(log, "%02X", 0);

                        if ((j + 1) % 2 == 0)
                            TextLog_Putc(log, ' ');
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
    CreateTCPFlagString(p, tcpFlags);
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
    TextLog_Print(log, "Len: %d\n", ntohs(p->udph->uh_len) - UDP_HEADER_LEN);
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
    uint32_t orig_ip_hlen;

    if (log == NULL || p == NULL)
        return;

    memset((char*)&op, 0, sizeof(op));
    orig_p = &op;

    orig_p->iph = p->orig_iph;
    orig_p->tcph = p->orig_tcph;
    orig_p->udph = p->orig_udph;
    orig_p->sp = p->orig_sp;
    orig_p->dp = p->orig_dp;
    orig_p->icmph = p->orig_icmph;
    orig_p->iph_api = p->orig_iph_api;
    orig_p->ip4h = p->orig_ip4h;
    orig_p->ip6h = p->orig_ip6h;
    orig_p->family = p->orig_family;

    if(orig_p->iph != NULL)
    {
        TextLog_Print(log, "\n** ORIGINAL DATAGRAM DUMP:\n");
        LogIPHeader(log, orig_p);
        orig_ip_hlen = ipv4::get_pkt_len(p->orig_iph) << 2;

        switch(GET_IPH_PROTO(orig_p))
        {
            case IPPROTO_TCP:
                if(orig_p->tcph != NULL)
                    TextLog_Print(log, "Seq: 0x%lX\n",
                            (u_long)ntohl(orig_p->tcph->th_seq));
                break;

            case IPPROTO_UDP:
                if(orig_p->udph != NULL)
                    TextLog_Print(log, "Len: %d  Csum: %d\n",
                            ntohs(orig_p->udph->uh_len) - UDP_HEADER_LEN,
                            ntohs(orig_p->udph->uh_chk));
                break;

            case IPPROTO_ICMP:
                if(orig_p->icmph != NULL)
                    LogEmbeddedICMPHeader(log, orig_p->icmph);
                break;

            default:
                TextLog_Print(log, "Protocol: 0x%X (unknown or "
                        "header truncated)", GET_IPH_PROTO(orig_p));
                break;
        }       /* switch */

        /* if more than 8 bytes of original IP payload sent */
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
    int next_layer, ip_start, ip_ob_start, ip_ob_end, byte_pos, char_pos;
    int i;

    next_layer = ip_start = byte_pos = char_pos = 0;

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
        next_layer =  p->next_layer;
        for ( i = 0; i < next_layer; i++ )
        {
            if ( p->layers[i].proto == PROTO_IP4
                  || p->layers[i].proto == PROTO_IP6
                )
            {
                if(p->layers[i].length && p->layers[i].start)
                break;
            }
        }

        ip_start = p->layers[i].start - data;

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
        i = 0;

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
        // FIXTHIS do we get here for portscan or sdf?
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

#define DATA_PTR(p) \
    ((uint8_t*)p->iph + (GET_IPH_HLEN(p) << 2))
#define DATA_LEN(p) \
    (p->actual_ip_len - (GET_IPH_HLEN(p) << 2))

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

        if ( p->mpls )
        {
            LogMPLSHeader(log, p);
        }

        if ( p->outer_iph )
        {
            LogOuterIPHeader(log, p);
            if ( p->greh )
                LogGREHeader(log, p);
        }
    }

    LogIPHeader(log, p);

    /* if this isn't a fragment, print the other header info */
    if ( !p->frag_flag )
    {
        switch (GET_IPH_PROTO(p))
        {
            case IPPROTO_TCP:
                if ( p->tcph != NULL )

                {
                    LogTCPHeader(log, p);
                }
                else
                {
                    LogNetData(log, DATA_PTR(p), DATA_LEN(p), NULL);
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
                    LogNetData(log, DATA_PTR(p), DATA_LEN(p), NULL);
                }

                break;

            case IPPROTO_ICMP:
                if ( p->icmph != NULL )
                {
                    LogICMPHeader(log, p);
                }
                else
                {
                    LogNetData(log, DATA_PTR(p), GET_IP_PAYLEN(p), NULL);
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
                LogCharData(log, (char *)file_data_ptr.data, file_data_ptr.len);
            }
            else if(!IsGzipData(p->flow))
            {
                TextLog_Print(log, "%s\n", "Decompressed Data for this packet");
                LogCharData(log, (char *)file_data_ptr.data, file_data_ptr.len);
            }
        }
        else
        {
            LogNetData(log, p->data, p->dsize, NULL);
            if(!IsJSNormData(p->flow))
            {
                TextLog_Print(log, "%s\n", "Normalized JavaScript for this packet");
                LogNetData(log, file_data_ptr.data, file_data_ptr.len, NULL);
            }
            else if(!IsGzipData(p->flow))
            {
                TextLog_Print(log, "%s\n", "Decompressed Data for this packet");
                LogNetData(log, file_data_ptr.data, file_data_ptr.len, NULL);
            }
        }
    }
    else if (ScVerboseByteDump())
    {
        LogNetData(log, p->pkt, p->pkth->caplen, p);
    }
}

#ifndef NO_NON_ETHER_DECODER
/*--------------------------------------------------------------------
 * ARP stuff cloned from log.c
 *--------------------------------------------------------------------
 */
void LogArpHeader(TextLog*, Packet*)
{
// XXX-IPv6 "NOT YET IMPLEMENTED - printing ARP header"
}
#endif


#if 0
// these must be converted to use TextLog 
// (or just deleted)
#ifndef NO_NON_ETHER_DECODER
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
static void PrintEapolKey(FILE * fp, Packet * p)
{
    uint16_t length;

    if(p->eapolk == NULL)
    {
        fprintf(fp, "Eapol Key truncated\n");
        return;
    }
    fprintf(fp, "KEY type: ");
    if (p->eapolk->type == 1) {
      fprintf(fp, "RC4");
    }

    memcpy(&length, &p->eapolk->length, 2);
    length = ntohs(length);
    fprintf(fp, " len: %d", length);
    fprintf(fp, " index: %d ", p->eapolk->index & 0x7F);
    fprintf(fp, p->eapolk->index & 0x80 ? " unicast\n" : " broadcast\n");
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
static void PrintEapolHeader(FILE * fp, Packet * p)
{
    fprintf(fp, "EAPOL type: ");
    switch(p->eplh->eaptype) {
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
    fprintf(fp, " Len: %d\n", ntohs(p->eplh->len));
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
static void PrintEAPHeader(FILE * fp, Packet * p)
{

    if(p->eaph == NULL)
    {
        fprintf(fp, "EAP header truncated\n");
        return;
    }
    fprintf(fp, "code: ");
    switch(p->eaph->code) {
    case EAP_CODE_REQUEST:
      fprintf(fp, "Req ");
      break;
    case EAP_CODE_RESPONSE:
      fprintf(fp, "Resp");
      break;
    case EAP_CODE_SUCCESS:
      fprintf(fp, "Succ");
      break;
    case EAP_CODE_FAILURE:
      fprintf(fp, "Fail");
      break;
    }
    fprintf(fp, " id: 0x%x len: %d", p->eaph->id, ntohs(p->eaph->len));
    if (p->eaptype != NULL) {
      fprintf(fp, " type: ");
      switch(*(p->eaptype)) {
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
    PrintEapolHeader(fp, p);
    if (p->eplh->eaptype == EAPOL_TYPE_EAP) {
      PrintEAPHeader(fp, p);
    }
    else if (p->eplh->eaptype == EAPOL_TYPE_KEY) {
      PrintEapolKey(fp, p);
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
#endif

