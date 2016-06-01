//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <time.h>
#include <sys/time.h>

#include "framework/inspector.h"
#include "ps_detect.h"

struct sfip_t;
struct PS_PROTO;
struct PS_TRACKER;
struct PS_PKT;
typedef InspectorData<PsCommon> PsData;

class PortScan : public Inspector
{
public:
    PortScan(class PortScanModule*);
    ~PortScan();

    bool configure(SnortConfig*) override;
    void show(SnortConfig*) override;

    void eval(Packet*) override;

    void tinit() override;
    void tterm() override;

private:
    void ps_parse(SnortConfig*, char*);

    int ps_ignore_ip(
        const sfip_t* scanner, uint16_t scanner_port,
        const sfip_t* scanned, uint16_t scanned_port);

    int ps_filter_ignore(PS_PKT* ps_pkt);
    int ps_tracker_lookup(
        PS_PKT* ps_pkt, PS_TRACKER** scanner, PS_TRACKER** scanned);

    int ps_get_proto(PS_PKT* ps_pkt, int* proto);
    int ps_proto_update_window(PS_PROTO* proto, time_t pkt_time);

    int ps_proto_update(
        PS_PROTO* proto, int ps_cnt, int pri_cnt, const sfip_t* ip,
        u_short port, time_t pkt_time);

    int ps_tracker_update(
        PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER* scanned);

    int ps_tracker_update_ip(
        PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER* scanned);

    int ps_tracker_update_tcp(
        PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER* scanned);

    int ps_tracker_update_udp(
        PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER* scanned);

    int ps_tracker_update_icmp(
        PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER* scanned);

    int ps_tracker_alert(
        PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER* scanned);

    int ps_alert_tcp(PS_PROTO* scanner, PS_PROTO* scanned);
    int ps_alert_ip(PS_PROTO* scanner, PS_PROTO* scanned);
    int ps_alert_udp(PS_PROTO* scanner, PS_PROTO* scanned);
    int ps_alert_icmp(PS_PROTO* scanner, PS_PROTO* scanned);

    int ps_detect(PS_PKT* ps_pkt);

private:
    PortscanConfig* config;
    PsData* global;
};

void ps_cleanup();
void ps_reset();

int ps_detect(PS_PKT* p);
void ps_tracker_print(PS_TRACKER* tracker);

void ps_init_hash(unsigned long);

#endif

