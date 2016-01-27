//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

//dce2_tcp.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifndef DCE2_TCP_H
#define DCE2_TCP_H

#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "framework/counts.h"

#define DCE2_TCP_NAME "dce_tcp"
#define DCE2_TCP_HELP "dce over tcp inspection"

struct dce2TcpStats
{
/*  FIXIT-M
    PegCount sessions_autodetected;
#ifdef DEBUG
    PegCount autoports[65535][DCE2_TRANS_TYPE__MAX];
#endif
*/
    PegCount events;
    PegCount sessions_aborted;
    PegCount bad_autodetects;

    PegCount tcp_sessions;
    PegCount tcp_pkts;

    PegCount co_pdus;
    PegCount co_bind;
    PegCount co_bind_ack;
    PegCount co_alter_ctx;
    PegCount co_alter_ctx_resp;
    PegCount co_bind_nack;
    PegCount co_request;
    PegCount co_response;
    PegCount co_cancel;
    PegCount co_orphaned;
    PegCount co_fault;
    PegCount co_auth3;
    PegCount co_shutdown;
    PegCount co_reject;
    PegCount co_other_req;
    PegCount co_other_resp;
    PegCount co_req_fragments;
    PegCount co_resp_fragments;
    PegCount co_cli_max_frag_size;
    PegCount co_cli_min_frag_size;
    PegCount co_cli_seg_reassembled;
    PegCount co_cli_frag_reassembled;
    PegCount co_srv_max_frag_size;
    PegCount co_srv_min_frag_size;
    PegCount co_srv_seg_reassembled;
    PegCount co_srv_frag_reassembled;
};

extern THREAD_LOCAL dce2TcpStats dce2_tcp_stats;

extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_main;
extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_session;
extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_new_session;
extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_session_state;
extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_detect;
extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_log;
extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_co_seg;
extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_co_frag;
extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_co_reass;
extern THREAD_LOCAL ProfileStats dce2_tcp_pstat_co_ctx;

#endif

