//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// ps_inspect.h author Russ Combs <rucombs@cisco.com>

#ifndef PS_INSPECT_H
#define PS_INSPECT_H

// The PortScan inspector is declared here.  The public methods and
// alerting methods are defined in port_scan.cc and the detection methods
// are in ps_detect.cc.

#include "framework/inspector.h"
#include "ps_detect.h"

namespace snort
{
struct SfIp;
}
struct PS_PROTO;
struct PS_TRACKER;
struct PS_PKT;

class PortScan : public snort::Inspector
{
public:
    PortScan(class PortScanModule*);
    ~PortScan() override;

    void show(snort::SnortConfig*) override;
    void eval(snort::Packet*) override;

    void tinit() override;
    void tterm() override;

private:
    void ps_parse(snort::SnortConfig*, char*);

    bool ps_ignore_ip( const snort::SfIp* scanner, uint16_t scanner_port,
        const snort::SfIp* scanned, uint16_t scanned_port);

    bool ps_filter_ignore(PS_PKT*);
    int ps_get_proto(PS_PKT*, int* proto);
    int ps_detect(PS_PKT*);

    bool ps_tracker_lookup(PS_PKT*, PS_TRACKER** scanner, PS_TRACKER** scanned);
    bool ps_tracker_update(PS_PKT*, PS_TRACKER* scanner, PS_TRACKER* scanned);
    bool ps_tracker_alert(PS_PKT*, PS_TRACKER* scanner, PS_TRACKER* scanned);

    void ps_proto_update_window(unsigned window, PS_PROTO*, time_t pkt_time);

    int ps_proto_update( PS_PROTO*, int ps_cnt, int pri_cnt, unsigned window, const snort::SfIp* ip,
        unsigned short port, time_t pkt_time);

    void ps_tracker_update_ip(PS_PKT*, PS_TRACKER* scanner, PS_TRACKER* scanned);
    void ps_tracker_update_tcp(PS_PKT*, PS_TRACKER* scanner, PS_TRACKER* scanned);
    void ps_tracker_update_udp(PS_PKT*, PS_TRACKER* scanner, PS_TRACKER* scanned);
    void ps_tracker_update_icmp(PS_PKT*, PS_TRACKER* scanner, PS_TRACKER* scanned);

    void ps_alert_ip(PS_PROTO* scanner, PS_PROTO* scanned);
    void ps_alert_tcp(PS_PROTO* scanner, PS_PROTO* scanned);
    void ps_alert_udp(PS_PROTO* scanner, PS_PROTO* scanned);
    void ps_alert_icmp(PS_PROTO* scanner, PS_PROTO* scanned);

private:
    PortscanConfig* config;
};

#endif

