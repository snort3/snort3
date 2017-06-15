//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
**  @author     Daniel Roelker <droelker@sourcefire.com>
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "detection/signature.h"
#include "events/event.h"
#include "filters/sfthreshold.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet_manager.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "ps_inspect.h"
#include "ps_module.h"

#define PROTO_BUFFER_SIZE 256

static THREAD_LOCAL Packet* g_tmp_pkt = nullptr;
static THREAD_LOCAL FILE* g_logfile = nullptr;

THREAD_LOCAL SimpleStats spstats;
THREAD_LOCAL ProfileStats psPerfStats;

/**
**  This routine makes the portscan payload for the events.  The listed
**  info is:
**    - priority count (number of error transmissions RST/ICMP UNREACH)
**    - connection count (number of protocol connections SYN)
**    - ip count (number of IPs that communicated with host)
**    - ip range (low to high range of IPs)
**    - port count (number of port changes that occurred on host)
**    - port range (low to high range of ports connected too)
*/
static bool MakeProtoInfo(PS_PROTO* proto, const uint8_t* buffer, unsigned& total_size)
{
    assert(buffer);

    int dsize = (g_tmp_pkt->max_dsize - total_size);

    if (dsize < PROTO_BUFFER_SIZE)
        return false;

    SfIp* ip1, * ip2;
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
            ip1->ntoa());

        /* Now print the high ip into the buffer.  This saves us
         * from having to copy the results of SfIp::ntoa (which is
         * a static buffer) to avoid the reuse of that buffer when
         * more than one use of SfIp::ntoa is within the same printf.
         */
        SnortSnprintfAppend((char*)buffer, PROTO_BUFFER_SIZE,
            "%s\n"
            "Port/Proto Count: %d\n"
            "Port/Proto Range: %d:%d\n",
            ip2->ntoa(),
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
            ip1->ntoa()
            );

        /* Now print the high ip into the buffer.  This saves us
         * from having to copy the results of SfIp::ntoa (which is
         * a static buffer) to avoid the reuse of that buffer when
         * more than one use of SfIp::ntoa is within the same printf.
         */
        SnortSnprintfAppend((char*)buffer, PROTO_BUFFER_SIZE,
            "%s\n"
            "Port/Proto Count: %d\n"
            "Port/Proto Range: %d:%d\n",
            ip2->ntoa(),
            proto->u_port_count,
            proto->low_p,
            proto->high_p);
    }

    dsize = SnortStrnlen((const char*)buffer, PROTO_BUFFER_SIZE);
    total_size += dsize;

    //  Set the payload size.  This is protocol independent.
    g_tmp_pkt->dsize = dsize;

    return true;
}

static void LogPortscanAlert(Packet* p, uint32_t event_id,
    uint32_t event_ref, uint32_t gid, uint32_t sid)
{
    if(!p->ptrs.ip_api.is_ip())
        return;

    /* Do not log if being suppressed */
    const SfIp* src_addr = p->ptrs.ip_api.get_src();
    const SfIp* dst_addr = p->ptrs.ip_api.get_dst();

    if ( sfthreshold_test(gid, sid, src_addr, dst_addr, p->pkth->ts.tv_sec) )
    {
        return;
    }

    char timebuf[TIMEBUF_SIZE];
    ts_print((struct timeval*)&p->pkth->ts, timebuf);
    fprintf(g_logfile, "Time: %s\n", timebuf);

    if (event_id)
        fprintf(g_logfile, "event_id: %u\n", event_id);
    else
        fprintf(g_logfile, "event_ref: %u\n", event_ref);

    fprintf(g_logfile, "%s ", p->ptrs.ip_api.get_src()->ntoa());
    fprintf(g_logfile, "-> %s\n", p->ptrs.ip_api.get_dst()->ntoa());
    fprintf(g_logfile, "%.*s\n", p->dsize, p->data);

    fflush(g_logfile);
}

static int GeneratePSSnortEvent(Packet* p, uint32_t gid, uint32_t sid)
{
    unsigned int event_id = 0;  // FIXIT-H eliminate this

    DetectionEngine de;
    de.queue_event(gid, sid);

    if (g_logfile)
        LogPortscanAlert(p, event_id, 0, gid, sid);

    return event_id;
}

/**
**  We have to generate open port events differently because we tag these
**  to the original portscan event.
**
**  @retval 0 success
*/
static int GenerateOpenPortEvent(
    Packet* p, uint32_t gid, uint32_t sid, uint32_t sig_rev, uint32_t cls,
    uint32_t pri, uint32_t event_ref, struct timeval& event_time, const char* msg)
{
    /*
    **  This means that we logged an open port, but we don't have a event
    **  reference for it, so we don't log a snort event.  We still keep
    **  track of it though.
    */
    if (!event_ref)
        return 0;

    /* reset the thresholding subsystem checks for this packet */
    sfthreshold_reset();

    SigInfo info;
    Event event(info);

    SetEvent(event, gid, sid, sig_rev, cls, pri, event_ref);

    event.ref_time.tv_sec  = event_time.tv_sec;
    event.ref_time.tv_usec = event_time.tv_usec;

    if (p)
    {
        /*
         * Do threshold test for suppression and thresholding.  We have to do it
         * here since these are tagged packets, which aren't subject to thresholding,
         * but we want to do it for open port events.
         */
        if ( sfthreshold_test(gid, sid, p->ptrs.ip_api.get_src(),
            p->ptrs.ip_api.get_dst(), p->pkth->ts.tv_sec) )
        {
            return 0;
        }

        CallLogFuncs(p, nullptr, &event, msg);
    }
    else
    {
        return -1;
    }

    if (g_logfile)
        LogPortscanAlert(p, 0, event_ref, gid, sid);

    return event.event_id;
}

//  Write out the open ports info for open port alerts.
static bool MakeOpenPortInfo(
    PS_PROTO*, const uint8_t* buffer, unsigned& total_size, void* user)
{
    assert(buffer);

    if ( !user )
        return false;

    int dsize = (g_tmp_pkt->max_dsize - total_size);

    if (dsize < PROTO_BUFFER_SIZE)
        return false;

    SnortSnprintf((char*)buffer, PROTO_BUFFER_SIZE,
        "Open Port: %hu\n", *((unsigned short*)user));

    dsize = SnortStrnlen((const char*)buffer, PROTO_BUFFER_SIZE);
    total_size += dsize;

    //  Set the payload size.  This is protocol independent.
    g_tmp_pkt->dsize = dsize;

    return true;
}

/*
**  We have to create this fake packet so portscan data can be passed
**  through the unified output.
**
**  We want to copy the network and transport layer headers into our
**  fake packet.
*/
static bool MakePortscanPkt(PS_PKT* ps_pkt, PS_PROTO* proto, int proto_type, void* user)
{
    Packet* p = (Packet*)ps_pkt->pkt;

    if (!p->has_ip())
        return false;

    EncodeFlags flags = ENC_FLAG_NET;

    if ( !ps_pkt->reverse_pkt )
        flags |= ENC_FLAG_FWD;

    PacketManager::encode_format(flags, p, g_tmp_pkt, PSEUDO_PKT_PS);

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
        return false;
    }

    if (g_tmp_pkt->is_ip4())
        ((IP4Hdr*)g_tmp_pkt->ptrs.ip_api.get_ip4h())->set_proto(IpProtocol::PORT_SCAN);

    else if (g_tmp_pkt->is_ip6())
        ((ip::IP6Hdr*)g_tmp_pkt->ptrs.ip_api.get_ip6h())->set_proto(IpProtocol::PORT_SCAN);

    else
        return false;

    unsigned int ip_size = 0;  // FIXIT-H this doesn't look correct

    switch (proto_type)
    {
    case PS_PROTO_TCP:
    case PS_PROTO_UDP:
    case PS_PROTO_ICMP:
    case PS_PROTO_IP:
        if ( !MakeProtoInfo(proto, g_tmp_pkt->data, ip_size) )
            return false;

        break;

    case PS_PROTO_OPEN_PORT:
        if ( !MakeOpenPortInfo(proto, g_tmp_pkt->data, ip_size, user) )
            return false;

        break;

    default:
        return false;
    }

    //  Let's finish up the IP header and checksum.
    PacketManager::encode_update(g_tmp_pkt);

    if (g_tmp_pkt->ptrs.ip_api.is_ip6())
        ((ip::IP6Hdr*)g_tmp_pkt->ptrs.ip_api.get_ip6h())->set_len((uint16_t)ip_size);

    return true;
}

static void PortscanAlertTcp(Packet* p, PS_PROTO* proto, int)
{
    assert(proto);

    unsigned int event_ref;
    bool portsweep = false;

    switch (proto->alerts)
    {
    case PS_ALERT_ONE_TO_ONE:
        event_ref = GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_TCP_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY:
        event_ref = GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_TCP_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP:
        event_ref = GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_TCP_PORTSWEEP);
        portsweep = true;
        break;

    case PS_ALERT_DISTRIBUTED:
        event_ref = GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_TCP_DISTRIBUTED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_FILTERED:
        event_ref = GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_TCP_FILTERED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
        event_ref = GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_TCP_FILTERED_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        event_ref = GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_TCP_PORTSWEEP_FILTERED);
        portsweep = true;
        break;

    case PS_ALERT_DISTRIBUTED_FILTERED:
        event_ref = GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN);
        break;

    default:
        return;
    }

    //  Set the current event reference information for any open ports.
    proto->event_ref  = event_ref;
    proto->event_time.tv_sec  = p->pkth->ts.tv_sec;
    proto->event_time.tv_usec = p->pkth->ts.tv_usec;

    //  Only log open ports for portsweeps after the alert has been generated.
    if (proto->open_ports_cnt and !portsweep)
    {
        for ( int iCtr = 0; iCtr < proto->open_ports_cnt; iCtr++ )
        {
            DAQ_PktHdr_t* pkth = (DAQ_PktHdr_t*)g_tmp_pkt->pkth;
            PS_PKT ps_pkt;

            memset(&ps_pkt, 0x00, sizeof(PS_PKT));
            ps_pkt.pkt = (void*)p;

            if ( !MakePortscanPkt(&ps_pkt, proto, PS_PROTO_OPEN_PORT,
                (void*)&proto->open_ports[iCtr]) )
                return;

            pkth->ts.tv_usec += 1;
            GenerateOpenPortEvent(g_tmp_pkt, GID_PORT_SCAN, PSNG_OPEN_PORT,
                0, 0, 3 , proto->event_ref, proto->event_time, PSNG_OPEN_PORT_STR);
        }
    }
}

static void PortscanAlertUdp(Packet* p, PS_PROTO* proto, int)
{
    assert(proto);

    switch (proto->alerts)
    {
    case PS_ALERT_ONE_TO_ONE:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_UDP_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_UDP_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_UDP_PORTSWEEP);
        break;

    case PS_ALERT_DISTRIBUTED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_UDP_DISTRIBUTED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_FILTERED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_UDP_FILTERED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_UDP_FILTERED_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_UDP_PORTSWEEP_FILTERED);
        break;

    case PS_ALERT_DISTRIBUTED_FILTERED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN);
        break;

    default:
        break;
    }
}

static void PortscanAlertIp(Packet* p, PS_PROTO* proto, int)
{
    assert(proto);

    switch (proto->alerts)
    {
    case PS_ALERT_ONE_TO_ONE:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_IP_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_IP_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_IP_PORTSWEEP);
        break;

    case PS_ALERT_DISTRIBUTED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_IP_DISTRIBUTED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_FILTERED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_IP_FILTERED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_IP_FILTERED_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_IP_PORTSWEEP_FILTERED);
        break;

    case PS_ALERT_DISTRIBUTED_FILTERED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN);
        break;

    default:
        break;
    }
}

static void PortscanAlertIcmp(Packet* p, PS_PROTO* proto, int)
{
    assert(proto);

    switch (proto->alerts)
    {
    case PS_ALERT_PORTSWEEP:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_ICMP_PORTSWEEP);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        GeneratePSSnortEvent(p, GID_PORT_SCAN, PSNG_ICMP_PORTSWEEP_FILTERED);
        break;

    default:
        break;
    }
}

static void PortscanAlert(PS_PKT* ps_pkt, PS_PROTO* proto, int proto_type)
{
    Packet* p = (Packet*)ps_pkt->pkt;
    g_tmp_pkt = DetectionEngine::set_next_packet();

    if (proto->alerts == PS_ALERT_OPEN_PORT)
    {
        if ( !MakePortscanPkt(ps_pkt, proto, PS_PROTO_OPEN_PORT, (void*)&p->ptrs.sp) )
            return;

        GenerateOpenPortEvent(g_tmp_pkt, GID_PORT_SCAN, PSNG_OPEN_PORT, 0, 0, 3,
            proto->event_ref, proto->event_time, PSNG_OPEN_PORT_STR);
    }
    else
    {
        if ( !MakePortscanPkt(ps_pkt, proto, proto_type, nullptr) )
            return;

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
    g_tmp_pkt = nullptr;
}

static void PrintIPPortSet(IP_PORT* p)
{
    char ip_str[80], output_str[80];

    SnortSnprintf(ip_str, sizeof(ip_str), "%s", p->ip.get_addr()->ntoa());

    if (p->notflag)
        SnortSnprintf(output_str, sizeof(output_str), "        !%s", ip_str);
    else
        SnortSnprintf(output_str, sizeof(output_str), "        %s", ip_str);

    if (((p->ip.get_family() == AF_INET6) and (p->ip.get_bits() != 128)) ||
        ((p->ip.get_family() == AF_INET ) and (p->ip.get_bits() != 32 )))
        SnortSnprintfAppend(output_str, sizeof(output_str), "/%d", p->ip.get_bits());

    SF_LNODE* cursor;
    PORTRANGE* pr =(PORTRANGE*)sflist_first(&p->portset.port_list, &cursor);

    if ( pr and pr->port_lo != 0 )
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

    LogMessage("Portscan Detection Config:\n");
    memset(buf, 0, STD_BUF + 1);

    SnortSnprintf(buf, STD_BUF + 1, "    Detect Protocols:  ");

    if ( config->detect_scans & PS_PROTO_TCP )
        sfsnprintfappend(buf, STD_BUF, "TCP ");  proto_cnt++;

    if ( config->detect_scans & PS_PROTO_UDP )
        sfsnprintfappend(buf, STD_BUF, "UDP ");  proto_cnt++;

    if ( config->detect_scans & PS_PROTO_ICMP )
        sfsnprintfappend(buf, STD_BUF, "ICMP "); proto_cnt++;

    if ( config->detect_scans & PS_PROTO_IP )
        sfsnprintfappend(buf, STD_BUF, "IP");    proto_cnt++;

    LogMessage("%s\n", buf);
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
    LogMessage("    Memcap (in bytes): %lu\n", config->common->memcap);

    LogMessage("    Number of Nodes:   %ld\n",
        config->common->memcap / (sizeof(PS_PROTO)*proto_cnt-1));

    if ( config->logfile )
        LogMessage("    Logfile:           %s\n", "yes");

    if (config->ignore_scanners)
    {
        LogMessage("    Ignore Scanner IP List:\n");
        SF_LNODE* cursor;

        IP_PORT* p = (IP_PORT*)sflist_first(&config->ignore_scanners->ip_list, &cursor);

        for ( ; p; p = (IP_PORT*)sflist_next(&cursor) )
            PrintIPPortSet(p);
    }

    if (config->ignore_scanned)
    {
        LogMessage("    Ignore Scanned IP List:\n");
        SF_LNODE* cursor;

        IP_PORT* p = (IP_PORT*)sflist_first(&config->ignore_scanned->ip_list, &cursor);

        for ( ; p; p = (IP_PORT*)sflist_next(&cursor) )
            PrintIPPortSet(p);
    }

    if (config->watch_ip)
    {
        LogMessage("    Watch IP List:\n");
        SF_LNODE* cursor;

        IP_PORT* p = (IP_PORT*)sflist_first(&config->watch_ip->ip_list, &cursor);

        for ( ; p; p = (IP_PORT*)sflist_next(&cursor) )
            PrintIPPortSet(p);
    }
}

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
    memset(&ps_pkt, 0x00, sizeof(PS_PKT));
    ps_pkt.pkt = (void*)p;

    ps_detect(&ps_pkt);

    if (ps_pkt.scanner and ps_pkt.scanner->proto.alerts and
        (ps_pkt.scanner->proto.alerts != PS_ALERT_GENERATED))
    {
        PortscanAlert(&ps_pkt, &ps_pkt.scanner->proto, ps_pkt.proto);
    }

    if (ps_pkt.scanned and ps_pkt.scanned->proto.alerts and
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
#else
const BaseApi* nin_port_scan[] =
#endif
{
    &sd_api.base,
    &sp_api.base,
    nullptr
};

