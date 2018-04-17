//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// sfportscan.c author Daniel Roelker <droelker@sourcefire.com>
// port_scan.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "ps_inspect.h"
#include "ps_module.h"

using namespace snort;

THREAD_LOCAL SimpleStats spstats;
THREAD_LOCAL ProfileStats psPerfStats;

static void make_port_scan_info(Packet* p, PS_PROTO* proto)
{
    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);

    SfIp* ip1 = &proto->low_ip;
    SfIp* ip2 = &proto->high_ip;

    char a1[INET6_ADDRSTRLEN];
    char a2[INET6_ADDRSTRLEN];

    ip1->ntop(a1, sizeof(a1));
    ip2->ntop(a2, sizeof(a2));

    char type;

    if ( proto->alerts == PS_ALERT_PORTSWEEP or proto->alerts == PS_ALERT_PORTSWEEP_FILTERED )
        type = 'd';
    else
        type = 'r';

    buf.len = safe_snprintf((char*)buf.data, sizeof(buf.data),
        "Priority Count: %d\n"
        "Connection Count: %d\n"
        "IP Count: %d\n"
        "Scanne%c IP Range: %s:%s\n"
        "Port/Proto Count: %d\n"
        "Port/Proto Range: %d:%d\n",
        proto->priority_count,
        proto->connection_count,
        proto->u_ip_count,
        type, a1, a2,
        proto->u_port_count,
        proto->low_p, proto->high_p);
}

static void make_open_port_info(Packet* p, PS_PROTO* proto)
{
    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);

    SfIp* ip1 = &proto->low_ip;
    char a1[INET6_ADDRSTRLEN];
    ip1->ntop(a1, sizeof(a1));

    buf.len += safe_snprintf((char*)buf.data+buf.len, sizeof(buf.data)-buf.len,
        "Scanned IP: %s\n"
        "Port Count: %d\n"
        "Open Ports:",
        a1,
        proto->open_ports_cnt);

    for ( int i = 0; i < proto->open_ports_cnt; i++ )
    {
        buf.len += safe_snprintf(
            (char*)buf.data + buf.len, sizeof(buf.data) - buf.len, " %hu", proto->open_ports[i]);
    }
    buf.len += safe_snprintf((char*)buf.data + buf.len, sizeof(buf.data) - buf.len, "\n");
}

#if 0
// FIXIT-L add open port for port sweeps
static void make_open_port_info(Packet* p, uint16_t port)
{
    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);
    
    SfIpString ip_str;

    buf.len = safe_snprintf((char*)buf.data, sizeof(buf.data),
        "Scanned IP: %s\n"
        "Open Port: %hu\n",
        p->ptrs.ip_api.get_src()->ntop(ip_str), port);
}
#endif

static void PortscanAlertTcp(Packet* p, PS_PROTO* proto)
{
    assert(proto);

    if ( proto->open_ports_cnt and proto->alerts != PS_ALERT_PORTSWEEP and
        proto->alerts != PS_ALERT_PORTSWEEP_FILTERED )
    {
        make_open_port_info(p, proto);
    }
    switch (proto->alerts)
    {
    case PS_ALERT_ONE_TO_ONE:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_TCP_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_TCP_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_TCP_PORTSWEEP);
        break;

    case PS_ALERT_DISTRIBUTED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_TCP_DISTRIBUTED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_TCP_FILTERED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_TCP_FILTERED_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_TCP_PORTSWEEP_FILTERED);
        break;

    case PS_ALERT_DISTRIBUTED_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN);
        break;

    default:
        return;
    }
}

static void PortscanAlertUdp(Packet*, PS_PROTO* proto)
{
    assert(proto);

    switch (proto->alerts)
    {
    case PS_ALERT_ONE_TO_ONE:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_UDP_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_UDP_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_UDP_PORTSWEEP);
        break;

    case PS_ALERT_DISTRIBUTED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_UDP_DISTRIBUTED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_UDP_FILTERED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_UDP_FILTERED_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_UDP_PORTSWEEP_FILTERED);
        break;

    case PS_ALERT_DISTRIBUTED_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN);
        break;

    default:
        break;
    }
}

static void PortscanAlertIp(Packet*, PS_PROTO* proto)
{
    assert(proto);

    switch (proto->alerts)
    {
    case PS_ALERT_ONE_TO_ONE:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_IP_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_IP_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_IP_PORTSWEEP);
        break;

    case PS_ALERT_DISTRIBUTED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_IP_DISTRIBUTED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_IP_FILTERED_PORTSCAN);
        break;

    case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_IP_FILTERED_DECOY_PORTSCAN);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_IP_PORTSWEEP_FILTERED);
        break;

    case PS_ALERT_DISTRIBUTED_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN);
        break;

    default:
        break;
    }
}

static void PortscanAlertIcmp(Packet*, PS_PROTO* proto)
{
    assert(proto);

    switch (proto->alerts)
    {
    case PS_ALERT_PORTSWEEP:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_ICMP_PORTSWEEP);
        break;

    case PS_ALERT_PORTSWEEP_FILTERED:
        DetectionEngine::queue_event(GID_PORT_SCAN, PSNG_ICMP_PORTSWEEP_FILTERED);
        break;

    default:
        break;
    }
}

static void PortscanAlert(PS_PKT* ps_pkt, PS_PROTO* proto, int proto_type)
{
    Packet* p = ps_pkt->pkt;
    make_port_scan_info(p, proto);

    switch (proto_type)
    {
    case PS_PROTO_TCP:
        PortscanAlertTcp(p, proto);
        break;

    case PS_PROTO_UDP:
        PortscanAlertUdp(p, proto);
        break;

    case PS_PROTO_ICMP:
        PortscanAlertIcmp(p, proto);
        break;

    case PS_PROTO_IP:
        PortscanAlertIp(p, proto);
        break;
    }
}

static void PrintIPPortSet(IP_PORT* p)
{
    char output_str[80];

    SfIpString ip_str;
    p->ip.get_addr()->ntop(ip_str);

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

    for (; pr != nullptr;
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

    LogMessage("Portscan Detection Config:\n");
    SnortSnprintf(buf, sizeof(buf), "    Detect Protocols:  ");

    if ( config->detect_scans & PS_PROTO_TCP )
        sfsnprintfappend(buf, sizeof(buf)-1, "TCP ");

    if ( config->detect_scans & PS_PROTO_UDP )
        sfsnprintfappend(buf, sizeof(buf)-1, "UDP ");

    if ( config->detect_scans & PS_PROTO_ICMP )
        sfsnprintfappend(buf, sizeof(buf)-1, "ICMP ");

    if ( config->detect_scans & PS_PROTO_IP )
        sfsnprintfappend(buf, sizeof(buf)-1, "IP");

    LogMessage("%s\n", buf);
    SnortSnprintf(buf, sizeof(buf), "    Detect Scan Type:  ");

    if (config->detect_scan_type & PS_TYPE_PORTSCAN)
        sfsnprintfappend(buf, sizeof(buf)-1, "portscan ");

    if (config->detect_scan_type & PS_TYPE_PORTSWEEP)
        sfsnprintfappend(buf, sizeof(buf)-1, "portsweep ");

    if (config->detect_scan_type & PS_TYPE_DECOYSCAN)
        sfsnprintfappend(buf, sizeof(buf)-1, "decoy_portscan ");

    if (config->detect_scan_type & PS_TYPE_DISTPORTSCAN)
        sfsnprintfappend(buf, sizeof(buf)-1, "distributed_portscan");

    LogMessage("%s\n", buf);
    LogMessage("    Memcap (in bytes): %lu\n", config->memcap);
    LogMessage("    Number of Nodes:   %ld\n", config->memcap / ps_node_size());

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
}

PortScan::~PortScan()
{
    if ( config )
        delete config;
}

void PortScan::tinit()
{
    ps_init_hash(config->memcap);
}

void PortScan::tterm()
{
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
    PS_PKT ps_pkt(p);

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

static Module* mod_ctor()
{ return new PortScanModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* sp_ctor(Module* m)
{ return new PortScan((PortScanModule*)m); }

static void sp_dtor(Inspector* p)
{ delete p; }

static void sp_reset()
{ ps_reset(); }

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
    PROTO_BIT__ANY_IP,
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
    &sp_api.base,
    nullptr
};

