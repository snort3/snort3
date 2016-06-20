//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

/*
**  @file       sfportscan.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      Portscan detection
**
**  NOTES
**    - User Configuration:  The following is a list of parameters that can
**      be configured through the user interface:
**
**      proto  { tcp udp icmp ip all }
**      scan_type { portscan portsweep decoy_portscan distributed_portscan all }
**      sense_level { high }    # high, medium, low
**      watch_ip { }            # list of IPs, CIDR blocks
**      ignore_scanners { }     # list of IPs, CIDR blocks
**      ignore_scanned { }      # list of IPs, CIDR blocks
**      memcap { 10000000 }     # number of max bytes to allocate
**      logfile { /tmp/ps.log } # file to log detailed portscan info
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <sys/types.h>
#include <errno.h>

#include <string>

#include "ps_detect.h"
#include "ps_inspect.h"
#include "ps_module.h"

#include "ipobj.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "protocols/packet_manager.h"
#include "protocols/packet.h"
#include "events/event.h"
#include "events/event_wrapper.h"
#include "filters/sfthreshold.h"
#include "utils/util.h"
#include "utils/sfsnprintfappend.h"
#include "framework/inspector.h"
#include "profiler/profiler.h"
#include "time/packet_time.h"
#include "detection/detect.h"

#define PROTO_BUFFER_SIZE 256

static THREAD_LOCAL Packet* g_tmp_pkt = NULL;
static THREAD_LOCAL FILE* g_logfile = NULL;

THREAD_LOCAL SimpleStats spstats;
THREAD_LOCAL ProfileStats psPerfStats;

/*
**  NAME
**    MakeProtoInfo::
*/
/**
**  This routine makes the portscan payload for the events.  The listed
**  info is:
**    - priority count (number of error transmissions RST/ICMP UNREACH)
**    - connection count (number of protocol connections SYN)
**    - ip count (number of IPs that communicated with host)
**    - ip range (low to high range of IPs)
**    - port count (number of port changes that occurred on host)
**    - port range (low to high range of ports connected too)
**
**  @return integer
**
**  @retval -1 buffer not large enough
**  @retval  0 successful
*/
static int MakeProtoInfo(PS_PROTO* proto, const u_char* buffer, u_int* total_size)
{
    int dsize;
    sfip_t* ip1, * ip2;

    if (!total_size || !buffer)
        return -1;

    dsize = (g_tmp_pkt->max_dsize - *total_size);

    if (dsize < PROTO_BUFFER_SIZE)
        return -1;

    ip1 = &proto->low_ip;
    ip2 = &proto->high_ip;

    if (proto->alerts == PS_ALERT_PORTSWEEP ||
        proto->alerts == PS_ALERT_PORTSWEEP_FILTERED)
    {
        SnortSnprintf((char*)buffer, PROTO_BUFFER_SIZE,
            "Priority Count: %d\n"
            "Connection Count: %d\n"
            "IP Count: %d\n"
            "Scanned IP Range: %s:",
            proto->priority_count,
            proto->connection_count,
            proto->u_ip_count,
            inet_ntoa(ip1));

        /* Now print the high ip into the buffer.  This saves us
         * from having to copy the results of inet_ntoa (which is
         * a static buffer) to avoid the reuse of that buffer when
         * more than one use of inet_ntoa is within the same printf.
         */
        SnortSnprintfAppend((char*)buffer, PROTO_BUFFER_SIZE,
            "%s\n"
            "Port/Proto Count: %d\n"
            "Port/Proto Range: %d:%d\n",
            inet_ntoa(ip2),
            proto->u_port_count,
            proto->low_p,
            proto->high_p);
    }
    else
    {
        SnortSnprintf((char*)buffer, PROTO_BUFFER_SIZE,
            "Priority Count: %d\n"
            "Connection Count: %d\n"
            "IP Count: %d\n"
            "Scanner IP Range: %s:",
            proto->priority_count,
            proto->connection_count,
            proto->u_ip_count,
            inet_ntoa(ip1)
            );

        /* Now print the high ip into the buffer.  This saves us
         * from having to copy the results of inet_ntoa (which is
         * a static buffer) to avoid the reuse of that buffer when
         * more than one use of inet_ntoa is within the same printf.
         */
        SnortSnprintfAppend((char*)buffer, PROTO_BUFFER_SIZE,
            "%s\n"
            "Port/Proto Count: %d\n"
            "Port/Proto Range: %d:%d\n",
            inet_ntoa(ip2),
            proto->u_port_count,
            proto->low_p,
            proto->high_p);
    }

    dsize = SnortStrnlen((const char*)buffer, PROTO_BUFFER_SIZE);
    *total_size += dsize;

    /*
    **  Set the payload size.  This is protocol independent.
    */
    g_tmp_pkt->dsize = dsize;

    return 0;
}

static int LogPortscanAlert(Packet* p, uint32_t event_id,
    uint32_t event_ref, uint32_t gen_id, uint32_t sig_id)
{
    char timebuf[TIMEBUF_SIZE];
    const sfip_t* src_addr;
    const sfip_t* dst_addr;

    if(!p->ptrs.ip_api.is_ip())
        return -1;

    /* Do not log if being suppressed */
    src_addr = p->ptrs.ip_api.get_src();
    dst_addr = p->ptrs.ip_api.get_dst();

    if ( sfthreshold_test(gen_id, sig_id, src_addr, dst_addr, p->pkth->ts.tv_sec) )
    {
        return 0;
    }

    ts_print((struct timeval*)&p->pkth->ts, timebuf);

    fprintf(g_logfile, "Time: %s\n", timebuf);

    if (event_id)
        fprintf(g_logfile, "event_id: %u\n", event_id);
    else
        fprintf(g_logfile, "event_ref: %u\n", event_ref);

    fprintf(g_logfile, "%s ", inet_ntoa(p->ptrs.ip_api.get_src()));
    fprintf(g_logfile, "-> %s\n", inet_ntoa(p->ptrs.ip_api.get_dst()));
    fprintf(g_logfile, "%.*s\n", p->dsize, p->data);

    fflush(g_logfile);

    return 0;
}

static int GeneratePSSnortEvent(Packet* p,uint32_t gen_id,uint32_t sig_id)
{
    unsigned int event_id;

    event_id = GenerateSnortEvent(p,gen_id,sig_id);

    if (g_logfile)
        LogPortscanAlert(p, event_id, 0, gen_id, sig_id);

    return event_id;
}

/*
**  NAME
**    GenerateOpenPortEvent::
*/
/**
**  We have to generate open port events differently because we tag these
**  to the original portscan event.
**
**  @return int
**
**  @retval 0 success
*/
static int GenerateOpenPortEvent(Packet* p, uint32_t gen_id, uint32_t sig_id,
    uint32_t sig_rev, uint32_t cls, uint32_t pri,
    uint32_t event_ref, struct timeval* event_time, const char* msg)
{
    Event event;

    /*
    **  This means that we logged an open port, but we don't have a event
    **  reference for it, so we don't log a snort event.  We still keep
    **  track of it though.
    */
    if (!event_ref)
        return 0;

    /* reset the thresholding subsystem checks for this packet */
    sfthreshold_reset();

    SetEvent(&event, gen_id, sig_id, sig_rev, cls, pri, event_ref);
    //CallAlertFuncs(p,msg,NULL,&event);

    event.ref_time.tv_sec  = event_time->tv_sec;
    event.ref_time.tv_usec = event_time->tv_usec;

    if (p)
    {
        /*
         * Do threshold test for suppression and thresholding.  We have to do it
         * here since these are tagged packets, which aren't subject to thresholding,
         * but we want to do it for open port events.
         */
        if ( sfthreshold_test(gen_id, sig_id, p->ptrs.ip_api.get_src(),
            p->ptrs.ip_api.get_dst(), p->pkth->ts.tv_sec) )
        {
            return 0;
        }

        CallLogFuncs(p, NULL, &event, msg);
    }
    else
    {
        return -1;
    }

    if (g_logfile)
        LogPortscanAlert(p, 0, event_ref, gen_id, sig_id);

    return event.event_id;
}

/*
**  NAME
**    MakeOpenPortInfo::
*/
/**
**  Write out the open ports info for open port alerts.
**
**  @return integer
*/
static int MakeOpenPortInfo(
    PS_PROTO*, const u_char* buffer, u_int* total_size, void* user)
{
    int dsize;

    if ( !total_size || !buffer || !user )
        return -1;

    dsize = (g_tmp_pkt->max_dsize - *total_size);

    if (dsize < PROTO_BUFFER_SIZE)
        return -1;

    SnortSnprintf((char*)buffer, PROTO_BUFFER_SIZE,
        "Open Port: %hu\n", *((unsigned short*)user));

    dsize = SnortStrnlen((const char*)buffer, PROTO_BUFFER_SIZE);
    *total_size += dsize;

    /*
    **  Set the payload size.  This is protocol independent.
    */
    g_tmp_pkt->dsize = dsize;

    return 0;
}

/*
**  NAME
**    MakePortscanPkt::
*/
/*
**  We have to create this fake packet so portscan data can be passed
**  through the unified output.
**
**  We want to copy the network and transport layer headers into our
**  fake packet.
**
*/
static int MakePortscanPkt(PS_PKT* ps_pkt, PS_PROTO* proto, int proto_type,
    void* user)
{
    unsigned int ip_size = 0;
    Packet* p = (Packet*)ps_pkt->pkt;
    EncodeFlags flags = ENC_FLAG_NET;

    if (!p->has_ip())
        return -1;

    if ( !ps_pkt->reverse_pkt )
        flags |= ENC_FLAG_FWD;

    if (p != g_tmp_pkt)
    {
        PacketManager::encode_format(flags, p, g_tmp_pkt, PSEUDO_PKT_PS);
    }

    switch (proto_type)
    {
    case PS_PROTO_TCP:
        g_tmp_pkt->ps_proto = IpProtocol::TCP;
        break;
    case PS_PROTO_UDP:
        g_tmp_pkt->ps_proto = IpProtocol::UDP;
        break;
    case PS_PROTO_ICMP:
        g_tmp_pkt->ps_proto = IpProtocol::ICMPV4;
        break;
    case PS_PROTO_IP:
        g_tmp_pkt->ps_proto = IpProtocol::IP;
        break;
    case PS_PROTO_OPEN_PORT:
        g_tmp_pkt->ps_proto = p->get_ip_proto_next();
        break;
    default:
        return -1;
    }

    if (g_tmp_pkt->is_ip4())
    {
        ((IP4Hdr*)g_tmp_pkt->ptrs.ip_api.get_ip4h())->set_proto(IpProtocol::PORT_SCAN);
    }
    else
    {
        // since ip_api.is_ip() && !ip4h, this is automatically ip6h
        ((ip::IP6Hdr*)g_tmp_pkt->ptrs.ip_api.get_ip6h())->set_proto(IpProtocol::PORT_SCAN);
    }

    switch (proto_type)
    {
    case PS_PROTO_TCP:
    case PS_PROTO_UDP:
    case PS_PROTO_ICMP:
    case PS_PROTO_IP:
        if (MakeProtoInfo(proto, g_tmp_pkt->data, &ip_size))
            return -1;

        break;

    case PS_PROTO_OPEN_PORT:
        if (MakeOpenPortInfo(proto, g_tmp_pkt->data, &ip_size, user))
            return -1;

        break;

    default:
        return -1;
    }

    /*
    **  Let's finish up the IP header and checksum.
    */
    PacketManager::encode_update(g_tmp_pkt);

    // FIXIT-L IP4 is gauranteed to have been set in update().  Is IP6() also gauranteed?
    if (g_tmp_pkt->ptrs.ip_api.is_ip6())
        ((ip::IP6Hdr*)g_tmp_pkt->ptrs.ip_api.get_ip6h())->set_len((uint16_t)ip_size);

    return 0;
}

static int PortscanAlertTcp(Packet* p, PS_PROTO* proto, int)
{
    int iCtr;
    unsigned int event_ref;
    int portsweep = 0;

    if (!proto)
        return -1;

    switch (proto->alerts)
    {
    case PS_ALERT_ONE_TO_ONE:
        event_ref = GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_TCP_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY:
        event_ref = GeneratePSSnortEvent(p,GID_PORT_SCAN, PSNG_TCP_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP:
        event_ref = GeneratePSSnortEvent(p,GID_PORT_SCAN, PSNG_TCP_PORTSWEEP);
        portsweep = 1;

        break;

    case PS_ALERT_DISTRIBUTED:
        event_ref = GeneratePSSnortEvent(p,GID_PORT_SCAN, PSNG_TCP_DISTRIBUTED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_FILTERED:
        event_ref = GeneratePSSnortEvent(p,GID_PORT_SCAN, PSNG_TCP_FILTERED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
        event_ref = GeneratePSSnortEvent(p,GID_PORT_SCAN, PSNG_TCP_FILTERED_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        event_ref = GeneratePSSnortEvent(p,GID_PORT_SCAN, PSNG_TCP_PORTSWEEP_FILTERED);
        portsweep = 1;
        break;

    case PS_ALERT_DISTRIBUTED_FILTERED:
        event_ref = GeneratePSSnortEvent(p,GID_PORT_SCAN,
            PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN);
        break;

    default:
        return 0;
    }

    /*
    **  Set the current event reference information for any open ports.
    */
    proto->event_ref  = event_ref;
    proto->event_time.tv_sec  = p->pkth->ts.tv_sec;
    proto->event_time.tv_usec = p->pkth->ts.tv_usec;

    /*
    **  Only log open ports for portsweeps after the alert has been
    **  generated.
    */
    if (proto->open_ports_cnt && !portsweep)
    {
        for (iCtr = 0; iCtr < proto->open_ports_cnt; iCtr++)
        {
            DAQ_PktHdr_t* pkth = (DAQ_PktHdr_t*)g_tmp_pkt->pkth;
            PS_PKT ps_pkt;

            memset(&ps_pkt, 0x00, sizeof(PS_PKT));
            ps_pkt.pkt = (void*)p;

            if (MakePortscanPkt(&ps_pkt, proto, PS_PROTO_OPEN_PORT,
                (void*)&proto->open_ports[iCtr]))
                return -1;

            pkth->ts.tv_usec += 1;
            GenerateOpenPortEvent(g_tmp_pkt,GID_PORT_SCAN,PSNG_OPEN_PORT,
                0,0,3, proto->event_ref, &proto->event_time,
                PSNG_OPEN_PORT_STR);
        }
    }

    return 0;
}

static int PortscanAlertUdp(Packet* p, PS_PROTO* proto, int)
{
    if (!proto)
        return -1;

    switch (proto->alerts)
    {
    case PS_ALERT_ONE_TO_ONE:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_UDP_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_UDP_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_UDP_PORTSWEEP);
        break;

    case PS_ALERT_DISTRIBUTED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_UDP_DISTRIBUTED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_FILTERED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_UDP_FILTERED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_UDP_FILTERED_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_UDP_PORTSWEEP_FILTERED);
        break;

    case PS_ALERT_DISTRIBUTED_FILTERED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,
            PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN);
        break;

    default:
        break;
    }

    return 0;
}

static int PortscanAlertIp(Packet* p, PS_PROTO* proto, int)
{
    if (!proto)
        return -1;

    switch (proto->alerts)
    {
    case PS_ALERT_ONE_TO_ONE:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_IP_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_IP_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_IP_PORTSWEEP);
        break;

    case PS_ALERT_DISTRIBUTED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_IP_DISTRIBUTED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_FILTERED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_IP_FILTERED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_IP_FILTERED_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_IP_PORTSWEEP_FILTERED);
        break;

    case PS_ALERT_DISTRIBUTED_FILTERED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN, PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN);
        break;

    default:
        break;
    }

    return 0;
}

static int PortscanAlertIcmp(Packet* p, PS_PROTO* proto, int)
{
    if (!proto)
        return -1;

    switch (proto->alerts)
    {
    case PS_ALERT_PORTSWEEP:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_ICMP_PORTSWEEP);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        GeneratePSSnortEvent(p,GID_PORT_SCAN,PSNG_ICMP_PORTSWEEP_FILTERED);
        break;

    default:
        break;
    }

    return 0;
}

static int PortscanAlert(PS_PKT* ps_pkt, PS_PROTO* proto, int proto_type)
{
    Packet* p;

    if (!ps_pkt || !ps_pkt->pkt)
        return -1;

    p = (Packet*)ps_pkt->pkt;

    if (proto->alerts == PS_ALERT_OPEN_PORT)
    {
        if (MakePortscanPkt(ps_pkt, proto, PS_PROTO_OPEN_PORT, (void*)&p->ptrs.sp))
            return -1;

        GenerateOpenPortEvent(g_tmp_pkt,GID_PORT_SCAN,PSNG_OPEN_PORT,0,0,3,
            proto->event_ref, &proto->event_time, PSNG_OPEN_PORT_STR);
    }
    else
    {
        if (MakePortscanPkt(ps_pkt, proto, proto_type, NULL))
            return -1;

        switch (proto_type)
        {
        case PS_PROTO_TCP:
            PortscanAlertTcp(g_tmp_pkt, proto, proto_type);
            break;

        case PS_PROTO_UDP:
            PortscanAlertUdp(g_tmp_pkt, proto, proto_type);
            break;

        case PS_PROTO_ICMP:
            PortscanAlertIcmp(g_tmp_pkt, proto, proto_type);
            break;

        case PS_PROTO_IP:
            PortscanAlertIp(g_tmp_pkt, proto, proto_type);
            break;
        }
    }

    sfthreshold_reset();

    return 0;
}

static void PrintIPPortSet(IP_PORT* p)
{
    char ip_str[80], output_str[80];
    PORTRANGE* pr;

    SnortSnprintf(ip_str, sizeof(ip_str), "%s", sfip_to_str(&p->ip));

    if (p->notflag)
        SnortSnprintf(output_str, sizeof(output_str), "        !%s", ip_str);
    else
        SnortSnprintf(output_str, sizeof(output_str), "        %s", ip_str);

    if (((p->ip.family == AF_INET6) && (p->ip.bits != 128)) ||
        ((p->ip.family == AF_INET ) && (p->ip.bits != 32 )))
        SnortSnprintfAppend(output_str, sizeof(output_str), "/%d", p->ip.bits);

    SF_LNODE* cursor;
    pr=(PORTRANGE*)sflist_first(&p->portset.port_list, &cursor);

    if ( pr && pr->port_lo != 0 )
        SnortSnprintfAppend(output_str, sizeof(output_str), " : ");

    for (; pr != 0;
        pr=(PORTRANGE*)sflist_next(&cursor) )
    {
        if ( pr->port_lo != 0)
        {
            SnortSnprintfAppend(output_str, sizeof(output_str), "%u", pr->port_lo);
            if ( pr->port_hi != pr->port_lo )
            {
                SnortSnprintfAppend(output_str, sizeof(output_str), "-%u", pr->port_hi);
            }
            SnortSnprintfAppend(output_str, sizeof(output_str), " ");
        }
    }
    LogMessage("%s\n", output_str);
}

static void PrintPortscanConf(PortscanConfig* config)
{
    char buf[STD_BUF + 1];
    int proto_cnt = 0;
    IP_PORT* p;

    LogMessage("Portscan Detection Config:\n");
    if (config->disabled)
    {
        LogMessage("    Portscan Detection: INACTIVE\n");
    }
    memset(buf, 0, STD_BUF + 1);
    if (!config->disabled)
    {
        SnortSnprintf(buf, STD_BUF + 1, "    Detect Protocols:  ");
        if (config->detect_scans & PS_PROTO_TCP)
        {
            sfsnprintfappend(buf, STD_BUF, "TCP ");  proto_cnt++;
        }
        if (config->detect_scans & PS_PROTO_UDP)
        {
            sfsnprintfappend(buf, STD_BUF, "UDP ");  proto_cnt++;
        }
        if (config->detect_scans & PS_PROTO_ICMP)
        {
            sfsnprintfappend(buf, STD_BUF, "ICMP "); proto_cnt++;
        }
        if (config->detect_scans & PS_PROTO_IP)
        {
            sfsnprintfappend(buf, STD_BUF, "IP");    proto_cnt++;
        }
        LogMessage("%s\n", buf);
    }

    if (!config->disabled)
    {
        memset(buf, 0, STD_BUF + 1);
        SnortSnprintf(buf, STD_BUF + 1, "    Detect Scan Type:  ");
        if (config->detect_scan_type & PS_TYPE_PORTSCAN)
            sfsnprintfappend(buf, STD_BUF, "portscan ");
        if (config->detect_scan_type & PS_TYPE_PORTSWEEP)
            sfsnprintfappend(buf, STD_BUF, "portsweep ");
        if (config->detect_scan_type & PS_TYPE_DECOYSCAN)
            sfsnprintfappend(buf, STD_BUF, "decoy_portscan ");
        if (config->detect_scan_type & PS_TYPE_DISTPORTSCAN)
            sfsnprintfappend(buf, STD_BUF, "distributed_portscan");
        LogMessage("%s\n", buf);
    }

    if (!config->disabled)
    {
        memset(buf, 0, STD_BUF + 1);
        SnortSnprintf(buf, STD_BUF + 1, "    Sensitivity Level: ");
        if (config->sense_level == PS_SENSE_HIGH)
            sfsnprintfappend(buf, STD_BUF, "High/Experimental");
        if (config->sense_level == PS_SENSE_MEDIUM)
            sfsnprintfappend(buf, STD_BUF, "Medium");
        if (config->sense_level == PS_SENSE_LOW)
            sfsnprintfappend(buf, STD_BUF, "Low");
        LogMessage("%s\n", buf);
    }

    LogMessage("    Memcap (in bytes): %lu\n", config->common->memcap);

    if (!config->disabled)
    {
        LogMessage("    Number of Nodes:   %ld\n",
            config->common->memcap / (sizeof(PS_PROTO)*proto_cnt-1));

        if ( config->logfile )
            LogMessage("    Logfile:           %s\n", "yes");

        if (config->ignore_scanners)
        {
            LogMessage("    Ignore Scanner IP List:\n");
            SF_LNODE* cursor;

            for (p = (IP_PORT*)sflist_first(&config->ignore_scanners->ip_list, &cursor);
                p;
                p = (IP_PORT*)sflist_next(&cursor))
            {
                PrintIPPortSet(p);
            }
        }

        if (config->ignore_scanned)
        {
            LogMessage("    Ignore Scanned IP List:\n");
            SF_LNODE* cursor;

            for (p = (IP_PORT*)sflist_first(&config->ignore_scanned->ip_list, &cursor);
                p;
                p = (IP_PORT*)sflist_next(&cursor))
            {
                PrintIPPortSet(p);
            }
        }

        if (config->watch_ip)
        {
            LogMessage("    Watch IP List:\n");
            SF_LNODE* cursor;

            for (p = (IP_PORT*)sflist_first(&config->watch_ip->ip_list, &cursor);
                p;
                p = (IP_PORT*)sflist_next(&cursor))
            {
                PrintIPPortSet(p);
            }
        }
    }
}

#if 0
static int PortscanGetProtoBits(int detect_scans)
{
    unsigned proto_bits = PktType::IP;

    if (detect_scans & PS_PROTO_IP)
    {
        proto_bits |= PktType::ICMP;
    }

    if (detect_scans & PS_PROTO_UDP)
    {
        proto_bits |= PktType::ICMP;
        proto_bits |= PktType::UDP;
    }

    if (detect_scans & PS_PROTO_ICMP)
        proto_bits |= PktType::ICMP;

    if (detect_scans & PS_PROTO_TCP)
    {
        proto_bits |= PktType::ICMP;
        proto_bits |= PktType::TCP;
    }

    return proto_bits;
}

#endif

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

PortScan::PortScan(PortScanModule* mod)
{
    config = mod->get_data();
    global = nullptr;
}

PortScan::~PortScan()
{
    if ( config )
        delete config;

    if ( global )
        InspectorManager::release(global);
}

bool PortScan::configure(SnortConfig* sc)
{
    global = (PsData*)InspectorManager::acquire(PSG_NAME, sc);
    config->common = global->data;
    return true;
}

void PortScan::tinit()
{
    g_tmp_pkt = new Packet;
    ps_init_hash(config->common->memcap);

    if ( !config->logfile )
        return;

    std::string name;
    get_instance_file(name, "portscan.log");
    g_logfile = fopen(name.c_str(), "a+");

    if ( !g_logfile )
    {
        FatalError("Portscan log file '%s' could not be opened: %s.\n",
            name.c_str(), get_error(errno));
    }
}

void PortScan::tterm()
{
    if ( g_logfile )
    {
        fclose(g_logfile);
        g_logfile = nullptr;
    }
    ps_cleanup();
    delete g_tmp_pkt;
    g_tmp_pkt = nullptr;
}

void PortScan::show(SnortConfig*)
{
    PrintPortscanConf(config);
}

void PortScan::eval(Packet* p)
{
    Profile profile(psPerfStats);

    assert(p->ptrs.ip_api.is_ip());

    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return;

    ++spstats.total_packets;

    PS_PKT ps_pkt;
    memset(&ps_pkt, 0x00, sizeof(PS_PKT)); // FIXIT-P don't zap unless necessary
    ps_pkt.pkt = (void*)p;

    /* See if there is already an exisiting node in the hash table */
    ps_detect(&ps_pkt);

    if (ps_pkt.scanner && ps_pkt.scanner->proto.alerts &&
        (ps_pkt.scanner->proto.alerts != PS_ALERT_GENERATED))
    {
        PortscanAlert(&ps_pkt, &ps_pkt.scanner->proto, ps_pkt.proto);
    }

    if (ps_pkt.scanned && ps_pkt.scanned->proto.alerts &&
        (ps_pkt.scanned->proto.alerts != PS_ALERT_GENERATED))
    {
        PortscanAlert(&ps_pkt, &ps_pkt.scanned->proto, ps_pkt.proto);
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* gmod_ctor()
{ return new PortScanGlobalModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* sd_ctor(Module* m)
{
    PortScanGlobalModule* mod = (PortScanGlobalModule*)m;
    PsCommon* com = mod->get_data();
    PsData* p = new PsData(com);
    return p;
}

static void sd_dtor(Inspector* p)
{ delete p; }

static const InspectApi sd_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        PSG_NAME,
        PSG_HELP,
        gmod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    (uint16_t)PktType::NONE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    sd_ctor,
    sd_dtor,
    nullptr, // ssn
    nullptr  // reset
};

//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new PortScanModule; }

static Inspector* sp_ctor(Module* m)
{
    return new PortScan((PortScanModule*)m);
}

static void sp_dtor(Inspector* p)
{
    delete p;
}

static void sp_reset()
{
    ps_reset();
}

static const InspectApi sp_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        PS_NAME,
        PS_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PROBE,
    (uint16_t)PktType::ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    sp_ctor,
    sp_dtor,
    nullptr, // ssn
    sp_reset // FIXIT-L only inspector using this, eliminate?
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &sd_api.base,
    &sp_api.base,
    nullptr
};
#else
const BaseApi* nin_port_scan_global = &sd_api.base;
const BaseApi* nin_port_scan = &sp_api.base;
#endif

