//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// tcp_tracker.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Dec 1, 2015

#include "profiler/profiler_defs.h"
#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_reassemblers.h"
#include "tcp_tracker.h"

TcpTracker::TcpTracker(bool client) :
    TcpStreamTracker(client), splitter(nullptr), normalizer(nullptr), reassembler(nullptr)
{
    tcp_event = TCP_MAX_EVENTS;
    init_tracker( );
}

TcpTracker::~TcpTracker(void)
{
    delete splitter;
    delete normalizer;
    delete reassembler;
}

void TcpTracker::init_tracker(void)
{
    memset(&s_mgr, 0, sizeof( StateMgr ) );
    s_mgr.state_queue = TcpStreamTracker::TCP_STATE_NONE;

    tcp_state = TcpStreamTracker::TCP_STATE_NONE;
    flush_policy = STREAM_FLPOLICY_IGNORE;
    memset(&paf_state, 0, sizeof( PAF_State ) );
    snd_una = snd_nxt = snd_wnd = 0;
    r_nxt_ack = r_win_base = iss = ts_last = ts_last_packet = 0;
    small_seg_count = wscale = mss = 0;
    memset(mac_addr, 0, 6);
    flags = 0;
    alert_count = 0;
    memset(alerts, 0, sizeof( alerts ) );

    delete splitter;
    splitter = nullptr;
    delete normalizer;
    normalizer =  nullptr;
    delete reassembler;
    reassembler = nullptr;
}

//-------------------------------------------------------------------------
// flush policy stuff
//-------------------------------------------------------------------------

void TcpTracker::init_flush_policy(void)
{
    if ( splitter == nullptr )
        flush_policy = STREAM_FLPOLICY_IGNORE;
    else if ( !normalizer->is_tcp_ips_enabled() )
        flush_policy = STREAM_FLPOLICY_ON_ACK;
    else
        flush_policy = STREAM_FLPOLICY_ON_DATA;
}

void TcpTracker::set_splitter(StreamSplitter* ss)
{
    if ( splitter )
        delete splitter;

    splitter = ss;

    if ( ss )
        paf_setup(&paf_state);
    else
        flush_policy = STREAM_FLPOLICY_IGNORE;
}

void TcpTracker::set_splitter(const Flow* flow)
{
    Inspector* ins = flow->gadget;

    if ( !ins )
        ins = flow->clouseau;

    if ( ins )
        set_splitter(ins->get_splitter(!client_tracker) );
    else
        set_splitter(new AtomSplitter(!client_tracker) );
}

void TcpTracker::init_on_syn_sent(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    tsd.get_flow()->set_session_flags(SSNFLAG_SEEN_CLIENT);
    if ( tsd.get_tcph()->are_flags_set(TH_CWR | TH_ECE) )
        tsd.get_flow()->set_session_flags(SSNFLAG_ECN_CLIENT_QUERY);

    iss = tsd.get_seq();
    snd_una = tsd.get_seq() + 1;
    if ( tsd.get_seq() == tsd.get_end_seq() )
        snd_nxt = snd_una;
    else
        snd_nxt = snd_una + ( tsd.get_end_seq() - tsd.get_seq() - 1 );

    snd_wnd =  tsd.get_win();
    ts_last_packet = tsd.get_pkt()->pkth->ts.tv_sec;

    flags |= normalizer->get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_ts();
    if (ts_last == 0)
        flags |= TF_TSTAMP_ZERO;
    flags |= tsd.init_mss(&mss);
    flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, FROM_CLIENT);
    set_splitter(tsd.get_flow() );
    init_flush_policy( );

    tcp_state = TcpStreamTracker::TCP_SYN_SENT;
}

void TcpTracker::init_on_syn_recv(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    reassembler->set_seglist_base_seq(tsd.get_seq() + 1);
    r_nxt_ack = tsd.get_seq() + 1;
    r_win_base = tsd.get_seq() + 1;

    cache_mac_address(tsd, FROM_CLIENT);
    set_splitter(tsd.get_flow() );
    init_flush_policy( );

    tcp_state = TcpStreamTracker::TCP_LISTEN;
}

void TcpTracker::init_on_synack_sent(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    DebugMessage(DEBUG_STREAM_STATE, "Creating new session tracker on SYN_ACK!\n");

    tsd.get_flow()->set_session_flags(SSNFLAG_SEEN_SERVER);
    if (tsd.get_tcph()->are_flags_set(TH_CWR | TH_ECE))
        tsd.get_flow()->set_session_flags(SSNFLAG_ECN_SERVER_REPLY);

    iss =tsd.get_seq();
    snd_una = tsd.get_seq() + 1;
    snd_nxt = snd_una;
    snd_wnd = tsd.get_win();

    reassembler->set_seglist_base_seq(tsd.get_ack() );
    r_win_base = tsd.get_ack();
    r_nxt_ack = tsd.get_ack();
    ts_last_packet = tsd.get_pkt()->pkth->ts.tv_sec;

    flags |= normalizer->get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_ts();
    if ( ts_last == 0 )
        flags |= TF_TSTAMP_ZERO;
    flags |= tsd.init_mss(&mss);
    flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, FROM_SERVER);
    set_splitter(tsd.get_flow() );
    init_flush_policy();

    tcp_state = TcpStreamTracker::TCP_SYN_RECV;
}

void TcpTracker::init_on_synack_recv(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    reassembler->set_seglist_base_seq(tsd.get_seq() + 1);
    iss = tsd.get_ack() - 1;
    r_nxt_ack = tsd.get_seq() + 1;
    r_win_base = tsd.get_seq() + 1;
    snd_nxt = tsd.get_ack();

    cache_mac_address(tsd, FROM_SERVER);
    set_splitter(tsd.get_flow() );
    init_flush_policy();

    tcp_state = TcpStreamTracker::TCP_SYN_SENT;
}

void TcpTracker::init_on_3whs_ack_sent(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    tsd.get_flow()->set_session_flags(SSNFLAG_SEEN_CLIENT);

    if ( tsd.get_tcph()->are_flags_set(TH_CWR | TH_ECE) )
        tsd.get_flow()->set_session_flags(SSNFLAG_ECN_CLIENT_QUERY);

    iss = tsd.get_seq();
    snd_una = tsd.get_seq() + 1;
    snd_nxt = tsd.get_seq() + 1;
    snd_wnd = tsd.get_win();
    ts_last_packet = tsd.get_pkt()->pkth->ts.tv_sec;
    flags |= normalizer->get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_ts();
    if (ts_last == 0)
        flags |= TF_TSTAMP_ZERO;
    flags |= tsd.init_mss(&mss);
    flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, FROM_CLIENT);
    set_splitter(tsd.get_flow() );
    init_flush_policy();
    tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
}

void TcpTracker::init_on_3whs_ack_recv(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    reassembler->set_seglist_base_seq(tsd.get_seq() + 1);
    r_nxt_ack = tsd.get_seq() + 1;
    r_win_base = tsd.get_seq() + 1;

    cache_mac_address(tsd, FROM_CLIENT);
    set_splitter(tsd.get_flow() );
    init_flush_policy();
    tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
}

void TcpTracker::init_on_data_seg_sent(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    iss = tsd.get_seq();
    snd_una = tsd.get_seq();
    snd_nxt = tsd.get_seq();
    snd_wnd = tsd.get_win();
    if ( tsd.get_direction() == FROM_SERVER )
    {
        r_win_base = tsd.get_ack();
        r_nxt_ack = tsd.get_ack();
        reassembler->set_seglist_base_seq(tsd.get_ack() );
    }
    else
    {
        r_win_base = 0;
        r_nxt_ack = 0;
    }

    ts_last_packet = tsd.get_pkt()->pkth->ts.tv_sec;
    flags |= normalizer->get_tcp_timestamp(tsd, 0);
    ts_last = tsd.get_ts();
    if (ts_last == 0)
        flags |= TF_TSTAMP_ZERO;
    flags |= tsd.init_mss(&mss);
    flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, tsd.get_direction() );
    set_splitter(tsd.get_flow() );
    init_flush_policy();
    tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
}

void TcpTracker::init_on_data_seg_recv(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    if ( tsd.get_direction() == FROM_SERVER )
        iss = tsd.get_ack() - 1;
    else
        snd_una = tsd.get_ack() - 1;

    r_nxt_ack = tsd.get_seq();
    r_win_base = tsd.get_seq();
    snd_wnd = 0; /* reset later */
    reassembler->set_seglist_base_seq(tsd.get_seq() );

    cache_mac_address(tsd, tsd.get_direction() );
    set_splitter(tsd.get_flow() );
    init_flush_policy();
    tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
}

void TcpTracker::print(void)
{
    LogMessage(" + TcpTracker +\n");
    LogMessage("    state:              %s\n", tcp_state_names[ tcp_state ]);
    LogMessage("    state_queue:    %s\n", tcp_state_names[ s_mgr.state_queue ]);
    LogMessage("    expected_flags: 0x%X\n", s_mgr.expected_flags);
    LogMessage("    transition_seq: 0x%X\n", s_mgr.transition_seq);
    LogMessage("    stq_get_seq:    %d\n", s_mgr.stq_get_seq);
    LogMessage("    iss:                0x%X\n", iss);
    LogMessage("    ts_last:            %u\n", ts_last);
    LogMessage("    wscale:             %u\n", wscale);
    LogMessage("    mss:                0x%08X\n", mss);
    LogMessage("    snd_una:            %X\n", snd_una);
    LogMessage("    snd_nxt:            %X\n", snd_nxt);
    LogMessage("    snd_win:            %u\n", snd_wnd);
    LogMessage("    rcv_nxt:            %X\n", rcv_nxt);
    LogMessage("    r_win_base:         %X\n", r_win_base);
}

