//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_none.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#include "stream/stream.h"

#include "tcp_module.h"
#include "tcp_tracker.h"
#include "tcp_session.h"
#include "tcp_normalizer.h"
#include "tcp_state_none.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#include "stream/libtcp/stream_tcp_unit_test.h"
#endif

TcpStateNone::TcpStateNone(TcpStateMachine& tsm, TcpSession& session) :
    TcpStateHandler(TcpStreamTracker::TCP_STATE_NONE, tsm), session(session)
{
}

TcpStateNone::~TcpStateNone()
{
}

bool TcpStateNone::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    Flow* flow = tsd.get_flow();
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    flow->ssn_state.direction = FROM_CLIENT;
    flow->session_state |= STREAM_STATE_SYN;

    if ( trk.is_3whs_required() || ( tsd.has_wscale() & TF_WSCALE ) ||
         ( tsd.get_pkt()->dsize > 0 ) )
    {
        trk.init_on_syn_sent(tsd);
        session.init_new_tcp_session(tsd);
        tcpStats.sessions_on_syn++;
    }

    return true;
}

bool TcpStateNone::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    if ( trk.is_3whs_required() || ( tsd.has_wscale() & TF_WSCALE ) ||
         ( tsd.get_pkt()->dsize > 0 ) )
    {
        trk.init_on_syn_recv(tsd);
        trk.normalizer->ecn_tracker(tsd.get_tcph(), trk.is_3whs_required() );
    }

    return true;
}

bool TcpStateNone::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    Flow* flow = tsd.get_flow();
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    /* SYN-ACK from server */
    if ( ( flow->session_state == STREAM_STATE_NONE)
        || ( flow->get_session_flags() & SSNFLAG_RESET ) )
    {
        DebugMessage(DEBUG_STREAM_STATE,
            "Stream SYN|ACK PACKET, set session directioon to FROM_SERVER.\n");
        flow->ssn_state.direction = FROM_SERVER;
    }

    flow->session_state |= STREAM_STATE_SYN_ACK;

    if ( !trk.is_3whs_required() || session.config->midstream_allowed(tsd.get_pkt()) )
    {
        trk.init_on_synack_sent(tsd);
        session.init_new_tcp_session(tsd);
        tcpStats.sessions_on_syn_ack++;
    }

    return true;
}

bool TcpStateNone::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    if ( !trk.is_3whs_required() || session.config->midstream_allowed(tsd.get_pkt()) )
    {
        trk.init_on_synack_recv(tsd);
    }

    trk.normalizer->ecn_tracker(tsd.get_tcph(), trk.is_3whs_required() );

    return true;
}

bool TcpStateNone::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    Flow* flow = tsd.get_flow();
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    if ( !tsd.get_tcph()->is_rst() && ( flow->session_state & STREAM_STATE_SYN_ACK ) )
    {
        /* FIXIT: do we need to verify the ACK field is >= the seq of the SYN-ACK?
                   3-way Handshake complete, create TCP session */
        flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED );
        trk.init_on_3whs_ack_sent(tsd);
        session.init_new_tcp_session(tsd);
        session.update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        tcpStats.sessions_on_3way++;
    }

    return true;
}

bool TcpStateNone::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    Flow* flow = tsd.get_flow();
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    if ( !tsd.get_tcph()->is_rst() && ( flow->session_state & STREAM_STATE_SYN_ACK ) )
    {
        trk.init_on_3whs_ack_recv(tsd);
        trk.normalizer->ecn_tracker(tsd.get_tcph(), trk.is_3whs_required() );
    }

    return true;
}

bool TcpStateNone::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    // FIXIT - are these necessary (see checks in TcpSession::process, but should get rid of those
    if ( !trk.is_3whs_required() || session.config->midstream_allowed(tsd.get_pkt()) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        flow->set_session_flags(SSNFLAG_MIDSTREAM);

        if (tsd.get_pkt()->ptrs.sp > tsd.get_pkt()->ptrs.dp)
        {
            flow->ssn_state.direction = FROM_CLIENT;
            flow->set_session_flags(SSNFLAG_SEEN_CLIENT);
        }
        else
        {
            flow->ssn_state.direction = FROM_SERVER;
            flow->set_session_flags(SSNFLAG_SEEN_SERVER);
        }

        trk.init_on_data_seg_sent(tsd);
        session.init_new_tcp_session(tsd);

        if ( flow->session_state & STREAM_STATE_ESTABLISHED )
            session.update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);

        tcpStats.sessions_on_data++;
    }

    return true;
}

bool TcpStateNone::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    if ( !trk.is_3whs_required() || session.config->midstream_allowed(tsd.get_pkt()) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        flow->set_session_flags(SSNFLAG_MIDSTREAM);

        if (tsd.get_pkt()->ptrs.sp > tsd.get_pkt()->ptrs.dp)
        {
            flow->ssn_state.direction = FROM_CLIENT;
            flow->set_session_flags(SSNFLAG_SEEN_CLIENT);
        }
        else
        {
            flow->ssn_state.direction = FROM_SERVER;
            flow->set_session_flags(SSNFLAG_SEEN_SERVER);
        }

        trk.init_on_data_seg_recv(tsd);
        trk.normalizer->ecn_tracker(tsd.get_tcph(), trk.is_3whs_required() );
    }

    return true;
}

bool TcpStateNone::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateNone::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateNone::rst_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateNone::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

#ifdef FOO  // FIXIT - UNIT_TEST need work!!
#include "tcp_normalizers.h"
#include "tcp_reassemblers.h"

TEST_CASE("TCP State None", "[tcp_none_state][stream_tcp]")
{
    // initialization code here
    Flow* flow = new Flow;
    TcpTracker* ctrk = new TcpTracker(true);
    TcpTracker* strk = new TcpTracker(false);
    TcpEventLogger* tel = new TcpEventLogger;
    TcpSession* session = new TcpSession(flow);
    TcpStateMachine* tsm =  new TcpStateMachine;
    TcpStateHandler* tsh = new TcpStateNone(*tsm, *session);
    ctrk->normalizer = TcpNormalizerFactory::create(session, StreamPolicy::OS_LINUX, ctrk, strk);
    strk->normalizer = TcpNormalizerFactory::create(session, StreamPolicy::OS_LINUX, strk, ctrk);
    ctrk->reassembler = TcpReassemblerFactory::create(session, ctrk, StreamPolicy::OS_LINUX,
        false);
    strk->reassembler = TcpReassemblerFactory::create(session, strk, StreamPolicy::OS_LINUX, true);

    SECTION("syn_packet")
    {
        Packet* pkt = get_syn_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("syn_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK(TcpStreamTracker::TCP_SYN_SENT_EVENT == ctrk->get_tcp_event() );
            //CHECK( ( ctrk->get_iss() == 9050 ) );
            //CHECK( ( ctrk->get_snd_una() == 9051 ) );
            //CHECK( ( ctrk->get_snd_nxt() == 9050 ) );
            //CHECK( ( ctrk->get_snd_wnd() == 8192 ) );
        }

        SECTION("syn_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("syn_ack_packet")
    {
        Packet* pkt = get_syn_ack_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("syn_ack_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        SECTION("syn_ack_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("ack_packet")
    {
        Packet* pkt = get_ack_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("ack_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        SECTION("ack_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("data_seg_packet")
    {
        Packet* pkt = get_data_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("data_seg_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        SECTION("data_seg_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("fin_packet")
    {
        Packet* pkt = get_fin_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("fin_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        SECTION("fin_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("rst_packet")
    {
        Packet* pkt = get_rst_packet(flow);
        REQUIRE( ( pkt != nullptr  ));

        SECTION("rst_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ));
        }

        SECTION("rst_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    delete flow;
    delete tsh;
    delete ctrk;
    delete strk;
}

#endif

