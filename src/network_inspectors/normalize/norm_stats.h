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
// norm_stats.h author cisco.com

#ifndef NORM_STATS_H
#define NORM_STATS_H

#include "framework/counts.h"
#include "main/thread.h"

#include "normalize.h"

enum PegCounts
{
    PC_IP4_TRIM,
    PC_IP4_TOS,
    PC_IP4_DF,
    PC_IP4_RF,
    PC_IP4_TTL,
    PC_IP4_OPTS,
    PC_ICMP4_ECHO,
    PC_IP6_TTL,
    PC_IP6_OPTS,
    PC_ICMP6_ECHO,
    PC_TCP_SYN_OPT,
    PC_TCP_OPT,
    PC_TCP_PAD,
    PC_TCP_RSV,
    PC_TCP_NS,
    PC_TCP_URP,
    PC_TCP_ECN_PKT,
    PC_TCP_TS_ECR,
    PC_TCP_REQ_URG,
    PC_TCP_REQ_PAY,
    PC_TCP_REQ_URP,

    // These peg counts are shared with stream_tcp
    PC_TCP_TRIM_SYN,
    PC_TCP_TRIM_RST,
    PC_TCP_TRIM_WIN,
    PC_TCP_TRIM_MSS,
    PC_TCP_ECN_SSN,
    PC_TCP_TS_NOP,
    PC_TCP_IPS_DATA,
    PC_TCP_BLOCK,

    PC_MAX
};

#define TCP_PEGS_START PC_TCP_TRIM_SYN

extern THREAD_LOCAL PegCount norm_stats[PC_MAX][NORM_MODE_MAX];
extern const PegInfo norm_names[];

#endif
