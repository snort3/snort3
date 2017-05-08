//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_tracker.h"

#include "log/messages.h"
#include "profiler/profiler_defs.h"

#include "tcp_module.h"
#include "tcp_normalizer.h"
#include "tcp_reassembler.h"

TcpTracker::TcpTracker(bool client, TcpSession* ssn) :
    TcpStreamTracker(client)
{
    session = ssn;
}

TcpTracker::~TcpTracker()
{
    delete splitter;
    delete normalizer;
    delete reassembler;
}

void TcpTracker::init_tcp_state(void )
{
    tcp_state = ( client_tracker ) ?
        TcpStreamTracker::TCP_STATE_NONE : TcpStreamTracker::TCP_LISTEN;
    flush_policy = STREAM_FLPOLICY_IGNORE;
    memset(&paf_state, 0, sizeof(paf_state));
    snd_una = snd_nxt = snd_wnd = 0;
    r_nxt_ack = r_win_base = iss = ts_last = ts_last_packet = 0;
    small_seg_count = wscale = mss = 0;
    tf_flags = 0;
    alert_count = 0;
    memset(&alerts, 0, sizeof(alerts));
    memset(&mac_addr, 0, sizeof(mac_addr));
    mac_addr_valid = false;
    fin_final_seq = 0;
    fin_seq_status = TcpStreamTracker::FIN_NOT_SEEN;
    fin_seq_set = false;
    rst_pkt_sent = false;
}

void TcpTracker::init_toolbox()
{
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

void TcpTracker::init_flush_policy()
{
    if ( splitter == nullptr )
        flush_policy = STREAM_FLPOLICY_IGNORE;
    else if ( normalizer->is_tcp_ips_enabled() )
        flush_policy = STREAM_FLPOLICY_ON_DATA;
    else
        flush_policy = STREAM_FLPOLICY_ON_ACK;
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

void TcpTracker::reset_splitter( void )
{
    if ( splitter )
        splitter->reset();
}

void TcpTracker::init_on_syn_sent(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    tsd.get_flow()->set_session_flags(SSNFLAG_SEEN_CLIENT);
    if ( tsd.get_tcph()->are_flags_set(TH_CWR | TH_ECE) )
        tsd.get_flow()->set_session_flags(SSNFLAG_ECN_CLIENT_QUERY);

    iss = tsd.get_seg_seq();
    snd_una = iss;
    snd_nxt = tsd.get_end_seq();
    snd_wnd =  tsd.get_seg_wnd();

    ts_last_packet = tsd.get_pkt()->pkth->ts.tv_sec;
    tf_flags |= normalizer->get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_ts();
    if (ts_last == 0)
        tf_flags |= TF_TSTAMP_ZERO;
    tf_flags |= tsd.init_mss(&mss);
    tf_flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, FROM_CLIENT);
    set_splitter(tsd.get_flow() );
    init_flush_policy( );

    tcpStats.sessions_on_syn++;
    tcp_state = TcpStreamTracker::TCP_SYN_SENT;
}

void TcpTracker::init_on_syn_recv(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    irs = tsd.get_seg_seq();
    // FIXIT-H can we really set the vars below now?
    r_nxt_ack = tsd.get_seg_seq() + 1;
    r_win_base = tsd.get_seg_seq() + 1;
    reassembler->set_seglist_base_seq(tsd.get_seg_seq() + 1);

    cache_mac_address(tsd, FROM_CLIENT);
    set_splitter(tsd.get_flow() );
    init_flush_policy( );

    tcp_state = TcpStreamTracker::TCP_SYN_RECV;
}

void TcpTracker::init_on_synack_sent(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    DebugMessage(DEBUG_STREAM_STATE, "Creating new session tracker on SYN_ACK!\n");

    tsd.get_flow()->set_session_flags(SSNFLAG_SEEN_SERVER);
    if (tsd.get_tcph()->are_flags_set(TH_CWR | TH_ECE))
        tsd.get_flow()->set_session_flags(SSNFLAG_ECN_SERVER_REPLY);

    iss = tsd.get_seg_seq();
    irs = tsd.get_seg_ack() - 1;
    snd_una = tsd.get_seg_seq();
    snd_nxt = tsd.get_end_seq();
    snd_wnd = tsd.get_seg_wnd();

    r_win_base = tsd.get_seg_ack();
    r_nxt_ack = tsd.get_seg_ack();
    reassembler->set_seglist_base_seq(tsd.get_seg_ack() );

    ts_last_packet = tsd.get_pkt()->pkth->ts.tv_sec;
    tf_flags |= normalizer->get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_ts();
    if ( ts_last == 0 )
        tf_flags |= TF_TSTAMP_ZERO;
    tf_flags |= tsd.init_mss(&mss);
    tf_flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, FROM_SERVER);
    set_splitter(tsd.get_flow() );
    init_flush_policy();

    tcpStats.sessions_on_syn_ack++;
    tcp_state = TcpStreamTracker::TCP_SYN_RECV;
}

void TcpTracker::init_on_synack_recv(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    iss = tsd.get_seg_ack() - 1;
    irs = tsd.get_seg_seq();
    snd_una = tsd.get_seg_ack();
    snd_nxt = snd_una;

    r_nxt_ack = tsd.get_seg_seq() + 1;
    r_win_base = tsd.get_seg_seq() + 1;
    reassembler->set_seglist_base_seq(tsd.get_seg_seq() + 1);

    cache_mac_address(tsd, FROM_SERVER);
    set_splitter(tsd.get_flow() );
    init_flush_policy();

    tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
}

void TcpTracker::init_on_3whs_ack_sent(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    tsd.get_flow()->set_session_flags(SSNFLAG_SEEN_CLIENT);

    if ( tsd.get_tcph()->are_flags_set(TH_CWR | TH_ECE) )
        tsd.get_flow()->set_session_flags(SSNFLAG_ECN_CLIENT_QUERY);

    iss = tsd.get_seg_seq();
    snd_una = tsd.get_seg_seq();
    snd_nxt = snd_una;
    snd_wnd = tsd.get_seg_wnd();

    r_win_base = tsd.get_seg_ack();
    r_nxt_ack = tsd.get_seg_ack();

    ts_last_packet = tsd.get_pkt()->pkth->ts.tv_sec;
    tf_flags |= normalizer->get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_ts();
    if (ts_last == 0)
        tf_flags |= TF_TSTAMP_ZERO;
    tf_flags |= tsd.init_mss(&mss);
    tf_flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, FROM_CLIENT);
    set_splitter(tsd.get_flow() );
    init_flush_policy();
    tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
}

void TcpTracker::init_on_3whs_ack_recv(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    iss = tsd.get_seg_ack() - 1;
    irs = tsd.get_seg_seq();
    snd_una = tsd.get_seg_ack();
    snd_nxt = snd_una;

    r_nxt_ack = tsd.get_seg_seq();
    r_win_base = tsd.get_seg_seq();
    reassembler->set_seglist_base_seq(tsd.get_seg_seq() + 1);

    cache_mac_address(tsd, FROM_CLIENT);
    set_splitter(tsd.get_flow() );
    init_flush_policy();

    tcpStats.sessions_on_3way++;
    tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
}

void TcpTracker::init_on_data_seg_sent(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    Flow* flow = tsd.get_flow();

    if ( flow->ssn_state.direction == FROM_CLIENT )
        flow->set_session_flags(SSNFLAG_SEEN_CLIENT);
    else
        flow->set_session_flags(SSNFLAG_SEEN_SERVER);

    // FIXIT-H should we init these?
    iss = tsd.get_seg_seq();
    irs = tsd.get_seg_ack();
    snd_una = tsd.get_seg_seq();
    snd_nxt = snd_una + tsd.get_seg_len();
    snd_wnd = tsd.get_seg_wnd();

    r_win_base = tsd.get_seg_ack();
    r_nxt_ack = tsd.get_seg_ack();
    reassembler->set_seglist_base_seq(tsd.get_seg_ack());

    ts_last_packet = tsd.get_pkt()->pkth->ts.tv_sec;
    tf_flags |= normalizer->get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_ts();
    if (ts_last == 0)
        tf_flags |= TF_TSTAMP_ZERO;
    tf_flags |= ( tsd.init_mss(&mss) | tsd.init_wscale(&wscale) );

    cache_mac_address(tsd, tsd.get_direction() );
    set_splitter(tsd.get_flow() );
    init_flush_policy();
    tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
}

void TcpTracker::init_on_data_seg_recv(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpNewSessPerfStats);

    iss = tsd.get_seg_ack();
    irs = tsd.get_seg_seq();
    snd_una = tsd.get_seg_ack();
    snd_nxt = snd_una;
    snd_wnd = 0; /* reset later */

    r_nxt_ack = tsd.get_seg_seq();
    r_win_base = tsd.get_seg_seq();
    reassembler->set_seglist_base_seq(tsd.get_seg_seq());

    cache_mac_address(tsd, tsd.get_direction() );
    set_splitter(tsd.get_flow() );
    init_flush_policy();

    tcpStats.sessions_on_data++;
    tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
}

void TcpTracker::finish_server_init(TcpSegmentDescriptor& tsd)
{
    iss = tsd.get_seg_seq();
    snd_una = tsd.get_seg_seq();
    snd_nxt = tsd.get_end_seq();
    snd_wnd = tsd.get_seg_wnd();

    // FIXIT-H move this to fin handler for syn_recv state ..
    //if ( tcph->is_fin() )
    //    server->set_snd_nxt(server->get_snd_nxt() - 1);

    tf_flags |= normalizer->get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_ts();
    if ( ts_last != 0 )
        ts_last_packet = tsd.get_pkt()->pkth->ts.tv_sec;
    else
        tf_flags |= TF_TSTAMP_ZERO;

    tf_flags |= ( tsd.init_mss(&mss) | tsd.init_wscale(&wscale) );
}

void TcpTracker::finish_client_init(TcpSegmentDescriptor& tsd)
{
    Flow* flow = tsd.get_flow();

    r_nxt_ack = tsd.get_end_seq();

    if ( !( flow->session_state & STREAM_STATE_MIDSTREAM ) )
    {
        reassembler->set_seglist_base_seq(tsd.get_seg_seq() + 1);
        r_win_base = tsd.get_end_seq();
    }
    else
    {
        reassembler->set_seglist_base_seq(tsd.get_seg_seq() );
        r_win_base = tsd.get_seg_seq();
    }
}

void TcpTracker::update_tracker_ack_recv(TcpSegmentDescriptor& tsd)
{
    if ( SEQ_GT(tsd.get_seg_ack(), snd_una) )
    {
        snd_una = tsd.get_seg_ack();
        if ( snd_nxt < snd_una )
            snd_nxt = snd_una;
    }
}

void TcpTracker::update_tracker_ack_sent(TcpSegmentDescriptor& tsd)
{
    // ** this is how we track the last seq number sent
    // as is l_unackd is the "last left" seq recvd
    //snd_una = tsd.get_seg_seq();

    // FIXIT-H add check to validate ack...

    if ( SEQ_GT(tsd.get_end_seq(), snd_nxt) )
        snd_nxt = tsd.get_end_seq();

    if ( !SEQ_EQ(r_win_base, tsd.get_seg_ack() ) )
        small_seg_count = 0;

#ifdef S5_PEDANTIC
    if ( SEQ_GT(tsd.get_seg_ack(), r_win_base) &&
        SEQ_LEQ(tsd.get_seg_ack(), r_nxt_ack) )
#else
    if ( SEQ_GT(tsd.get_seg_ack(), r_win_base) )
#endif
        r_win_base = tsd.get_seg_ack();

    if ( ( fin_seq_status == TcpStreamTracker::FIN_WITH_SEQ_SEEN )
        && SEQ_EQ(r_win_base, fin_final_seq) )
    {
        fin_seq_status = TcpStreamTracker::FIN_WITH_SEQ_ACKED;
    }

    snd_wnd = tsd.get_seg_wnd();
    reassembler->flush_on_ack_policy(tsd.get_pkt() );
}

bool TcpTracker::update_on_3whs_ack(TcpSegmentDescriptor& tsd)
{
    bool good_ack = true;

    if ( is_ack_valid(tsd.get_seg_ack()) )
    {
        Flow* flow = tsd.get_flow();

        irs = tsd.get_seg_seq();
        finish_client_init(tsd);
        update_tracker_ack_recv(tsd);
        flow->set_session_flags(SSNFLAG_ESTABLISHED);
        flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED );

        /* Indicate this packet completes 3-way handshake */
        tsd.get_pkt()->packet_flags |= PKT_STREAM_TWH;
        tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
    }
    else
    {
        DebugFormat(DEBUG_STREAM_STATE,
            "Pkt Ack is Out of Bounds (%X, %X, %X) = (snd_una, snd_nxt, cur)\n",
            snd_una, snd_nxt, tsd.get_seg_ack());
        inc_tcp_discards();
        normalizer->trim_win_payload(tsd);
        good_ack = false;
    }

    return good_ack;
}

bool TcpTracker::update_on_rst_recv(TcpSegmentDescriptor& tsd)
{
    bool good_rst = true;

    normalizer->trim_rst_payload(tsd);
    if ( normalizer->validate_rst(tsd) )
    {
        Flow* flow = tsd.get_flow();

        DebugMessage(DEBUG_STREAM_STATE, "Received Valid RST, bailing\n");
        flow->set_session_flags(SSNFLAG_RESET);
        if ( normalizer->is_tcp_ips_enabled() )
            tcp_state = TcpStreamTracker::TCP_CLOSED;
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "Received RST with bad sequence number, bailing\n");
        inc_tcp_discards();
        normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
        good_rst = false;
    }

    return good_rst;
}

void TcpTracker::update_on_rst_sent()
{
    tcp_state = TcpStreamTracker::TCP_CLOSED;
    rst_pkt_sent = true;
}

void TcpTracker::flush_data_on_fin_recv(TcpSegmentDescriptor& tsd)
{
    if ( (flush_policy != STREAM_FLPOLICY_ON_ACK)
        && (flush_policy != STREAM_FLPOLICY_ON_DATA)
        && normalizer->is_tcp_ips_enabled())
    {
        tsd.get_pkt()->packet_flags |= PKT_PDU_TAIL;
    }

    reassembler->flush_on_data_policy(tsd.get_pkt());
}

bool TcpTracker::update_on_fin_recv(TcpSegmentDescriptor& tsd)
{
    if ( SEQ_LT(tsd.get_end_seq(), r_win_base) )
    {
        DebugMessage(DEBUG_STREAM_STATE, "FIN inside r_win_base, bailing\n");
        return false;
    }

    //--------------------------------------------------
    // FIXIT-L don't bump r_nxt_ack unless FIN is in seq
    // because it causes bogus 129:5 cases
    // but doing so causes extra gaps
    //if ( SEQ_EQ(tsd.end_seq, r_nxt_ack) )
    r_nxt_ack++;

    // set final seq # any packet rx'ed with seq > is bad
    if ( !fin_seq_set )
    {
        fin_final_seq = tsd.get_end_seq();
        fin_seq_set = true;
        if( tsd.get_seg_len() == 0 )
            fin_seq_status = TcpStreamTracker::FIN_WITH_SEQ_SEEN;
    }

    return true;
}

bool TcpTracker::update_on_fin_sent(TcpSegmentDescriptor& tsd)
{
    update_tracker_ack_sent(tsd);
    snd_nxt++;
    return true;
}

#ifdef S5_PEDANTIC
// From RFC 793:
//
//    Segment Receive  Test
//    Length  Window
//    ------- -------  -------------------------------------------
//
//       0       0     SEG.SEQ = RCV.NXT
//
//       0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
//
//      >0       0     not acceptable
//
//      >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
//                     or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
//
bool ValidSeq(const Packet* p, Flow* flow, TcpTracker* st, TcpSegmentDescriptor& tsd)
{
    uint32_t win = normalizer->get_stream_window(flow, st, tsd);

    if ( !p->dsize )
    {
        if ( !win )
        {
            return ( tsd.get_seg_seq() == r_win_base );
        }
        return SEQ_LEQ(r_win_base, tsd.get_seg_seq()) &&
               SEQ_LT(tsd.get_seg_seq(), r_win_base+win);
    }
    if ( !win )
        return 0;

    if ( SEQ_LEQ(r_win_base, tsd.get_seg_seq()) &&
        SEQ_LT(tsd.get_seg_seq(), r_win_base+win) )
        return 1;

    return SEQ_LEQ(r_win_base, tsd.get_end_seq()) &&
           SEQ_LT(tsd.get_end_seq(), r_win_base+win);
}

#endif

bool TcpTracker::is_segment_seq_valid(TcpSegmentDescriptor& tsd)
{
    bool valid_seq = true;

    int right_ok;
    uint32_t left_seq;

    DebugFormat(DEBUG_STREAM_STATE,
        "Checking end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
        tsd.get_end_seq(), r_win_base, tsd.get_seg_seq(),
        r_nxt_ack + normalizer->get_stream_window(tsd));

    if ( SEQ_LT(r_nxt_ack, r_win_base) )
        left_seq = r_nxt_ack;
    else
        left_seq = r_win_base;

    if ( tsd.get_seg_len() )
        right_ok = SEQ_GT(tsd.get_end_seq(), left_seq);
    else
        right_ok = SEQ_GEQ(tsd.get_end_seq(), left_seq);

    if ( right_ok )
    {
        uint32_t win = normalizer->get_stream_window(tsd);

        if ( SEQ_LEQ(tsd.get_seg_seq(), r_win_base + win) )
        {
            DebugMessage(DEBUG_STREAM_STATE, "seq is within window!\n");
        }
        else
        {
            DebugMessage(DEBUG_STREAM_STATE, "seq is past the end of the window!\n");
            valid_seq = false;
        }
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "end_seq is before win_base\n");
        valid_seq = false;
    }

    if ( !valid_seq )
    {
        inc_tcp_discards();
        normalizer->trim_win_payload(tsd);
    }

    return valid_seq;
}

void TcpTracker::print()
{
    LogMessage(" + TcpTracker +\n");
    LogMessage("    state:              %s\n", tcp_state_names[ tcp_state ]);
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

