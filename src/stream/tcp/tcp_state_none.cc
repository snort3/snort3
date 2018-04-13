//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_none.h"

#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

TcpStateNone::TcpStateNone(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_STATE_NONE, tsm)
{
}

bool TcpStateNone::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();
    flow->ssn_state.direction = FROM_CLIENT;
    flow->session_state |= STREAM_STATE_SYN;

    trk.init_on_syn_sent(tsd);
    trk.session->init_new_tcp_session(tsd);
    return true;
}

bool TcpStateNone::syn_recv(TcpSegmentDescriptor&, TcpStreamTracker&)
{
    // FIXIT-H syn received on undefined client, figure this out and do the right thing
    return true;
}

bool TcpStateNone::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();

    if ( !trk.session->config->require_3whs() or
         trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        flow->session_state |= ( STREAM_STATE_SYN | STREAM_STATE_SYN_ACK );
        trk.init_on_synack_sent(tsd);
        trk.session->init_new_tcp_session(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        trk.init_on_synack_recv(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
        if ( tsd.get_seg_len() > 0 )
            trk.session->handle_data_segment(tsd);
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) && ( tsd.has_wscale() ||
        ( tsd.get_seg_len() > 0 ) ) )
    {
        Flow* flow = tsd.get_flow();

        // FIXIT-H do we need to verify the ACK field is >= the seq of the SYN-ACK?
        // 3-way Handshake complete, create TCP session
        flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_SYN_ACK |
            STREAM_STATE_ESTABLISHED );
        trk.init_on_3whs_ack_sent(tsd);
        trk.session->init_new_tcp_session(tsd);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) && ( tsd.has_wscale() ||
        ( tsd.get_seg_len() > 0 ) ) )
    {
        Flow* flow = tsd.get_flow();

        if ( !tsd.get_tcph()->is_rst() && ( flow->session_state & STREAM_STATE_SYN_ACK ) )
        {
            trk.init_on_3whs_ack_recv(tsd);
            trk.normalizer.ecn_tracker(
                tsd.get_tcph(), trk.session->config->require_3whs());
        }
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        flow->set_session_flags(SSNFLAG_MIDSTREAM);

        trk.init_on_data_seg_sent(tsd);
        trk.session->init_new_tcp_session(tsd);

        if ( flow->session_state & STREAM_STATE_ESTABLISHED )
            trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        flow->set_session_flags(SSNFLAG_MIDSTREAM);

        trk.init_on_data_seg_recv(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
        trk.session->handle_data_segment(tsd);
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        // FIXIT-H handle FIN on midstream
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        // FIXIT-H handle FIN on midstream
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::rst_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        // FIXIT-H handle RST on midstream
    }
    return true;
}

bool TcpStateNone::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.update_on_rst_recv(tsd) )
    {
        trk.session->update_session_on_rst(tsd, false);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        trk.session->set_pkt_action_flag(ACTION_RST);
    }
    else
    {
        trk.session->tel.set_tcp_event(EVENT_BAD_RST);
    }
    return true;
}

#ifdef FOO  // FIXIT-H UNIT_TEST need work
#include "tcp_normalizers.h"
#include "tcp_reassemblers.h"

TEST_CASE("TCP State None", "[tcp_none_state][stream_tcp]")
{
    // initialization code here
    Flow* flow = new Flow;
    TcpStreamTracker* ctrk = new TcpStreamTracker(true);
    TcpStreamTracker* strk = new TcpStreamTracker(false);
    TcpEventLogger* tel = new TcpEventLogger;
    TcpSession* session = new TcpSession(flow);
    TcpStateMachine* tsm =  new TcpStateMachine;
    TcpStateHandler* tsh = new TcpStateNone(*tsm, *session);

    ctrk->normalizer = TcpNormalizerFactory::create(StreamPolicy::OS_LINUX, session, ctrk, strk);
    strk->normalizer = TcpNormalizerFactory::create(StreamPolicy::OS_LINUX, session, strk, ctrk);
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

