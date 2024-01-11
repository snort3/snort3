//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
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
// norm_stats.cc author cisco.com

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "norm_stats.h"

const PegInfo norm_names[] =
{
    { CountType::SUM, "ip4_trim", "eth packets trimmed to datagram size" },
    { CountType::SUM, "ip4_tos", "type of service normalizations" },
    { CountType::SUM, "ip4_df", "don't frag bit normalizations" },
    { CountType::SUM, "ip4_rf", "reserved flag bit clears" },
    { CountType::SUM, "ip4_ttl", "time-to-live normalizations" },
    { CountType::SUM, "ip4_opts", "ip4 options cleared" },
    { CountType::SUM, "icmp4_echo", "icmp4 ping normalizations" },
    { CountType::SUM, "ip6_hops", "ip6 hop limit normalizations" },
    { CountType::SUM, "ip6_options", "ip6 options cleared" },
    { CountType::SUM, "icmp6_echo", "icmp6 echo normalizations" },
    { CountType::SUM, "tcp_syn_options", "SYN only options cleared from non-SYN packets" },
    { CountType::SUM, "tcp_options", "packets with options cleared" },
    { CountType::SUM, "tcp_padding", "packets with padding cleared" },
    { CountType::SUM, "tcp_reserved", "packets with reserved bits cleared" },
    { CountType::SUM, "tcp_nonce", "packets with nonce bit cleared" },
    { CountType::SUM, "tcp_urgent_ptr", "packets without data with urgent pointer cleared" },
    { CountType::SUM, "tcp_ecn_pkt", "packets with ECN bits cleared" },
    { CountType::SUM, "tcp_ts_ecr", "timestamp cleared on non-ACKs" },
    { CountType::SUM, "tcp_req_urg", "cleared urgent pointer when urgent flag is not set" },
    { CountType::SUM, "tcp_req_pay",
        "cleared urgent pointer and urgent flag when there is no payload" },
    { CountType::SUM, "tcp_req_urp", "cleared the urgent flag if the urgent pointer is not set" },

    // These peg counts are shared with stream_tcp
    { CountType::SUM, "tcp_trim_syn", "tcp segments trimmed on SYN" },
    { CountType::SUM, "tcp_trim_rst", "RST packets with data trimmed" },
    { CountType::SUM, "tcp_trim_win", "data trimmed to window" },
    { CountType::SUM, "tcp_trim_mss", "data trimmed to MSS" },
    { CountType::SUM, "tcp_ecn_session", "ECN bits cleared" },
    { CountType::SUM, "tcp_ts_nop", "timestamp options cleared" },
    { CountType::SUM, "tcp_ips_data", "normalized segments" },
    { CountType::SUM, "tcp_block", "blocked segments" },

    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL PegCount norm_stats[PC_MAX][NORM_MODE_MAX];
