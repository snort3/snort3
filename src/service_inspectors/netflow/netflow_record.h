//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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

// netflow_record.h author Michael Matirko <mmatirkoe@cisco.com>

#ifndef NETFLOW_RECORD_H
#define NETFLOW_RECORD_H

#include "sfip/sf_ip.h"

struct NetFlowSessionRecord
{
    snort::SfIp initiator_ip;
    snort::SfIp responder_ip;
    snort::SfIp next_hop_ip;
    snort::SfIp netflow_initiator_ip;
    uint8_t proto;
    uint16_t initiator_port;
    uint16_t responder_port;
    uint32_t first_pkt_second;
    uint32_t last_pkt_second;
    uint64_t initiator_pkts;
    uint64_t responder_pkts;
    uint64_t initiator_bytes;
    uint64_t responder_bytes;
    uint8_t tcp_flags;

    uint32_t nf_src_as;
    uint32_t nf_dst_as;
    uint32_t nf_snmp_in;
    uint32_t nf_snmp_out;
    uint8_t nf_src_tos;
    uint8_t nf_dst_tos;
    uint8_t nf_src_mask;
    uint8_t nf_dst_mask;
};

#endif
