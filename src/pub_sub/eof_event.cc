//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// eof_event.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eof_event.h"

#include "stream/tcp/tcp_session.h"
#include "stream/udp/udp_session.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
//  History
//-------------------------------------------------------------------------

static void one_side_history(const TcpSession* ssn, string& history, bool client)
{
    const auto& events = client ? ssn->tcp_ssn_stats.client_events : ssn->tcp_ssn_stats.server_events;
    if (events.test(TcpStreamTracker::TcpEvent::TCP_SYN_SENT_EVENT))
        history += client ? "S" : "s";
    if (events.test(TcpStreamTracker::TcpEvent::TCP_SYN_ACK_SENT_EVENT))
        history += client ? "H" : "h";
    if (events.test(TcpStreamTracker::TcpEvent::TCP_ACK_SENT_EVENT))
        history += client ? "A" : "a";
    if (events.test(TcpStreamTracker::TcpEvent::TCP_DATA_SEG_SENT_EVENT))
        history += client ? "D" : "d";
    if (events.test(TcpStreamTracker::TcpEvent::TCP_FIN_SENT_EVENT))
        history += client ? "F" : "f";
    if (events.test(TcpStreamTracker::TcpEvent::TCP_RST_SENT_EVENT))
        history += client ? "R" : "r";
}

static void get_tcp_history(const TcpSession* ssn, string& history)
{
    one_side_history(ssn, history, true);
    one_side_history(ssn, history, false);
}

static void get_udp_history(const UdpSession* ssn, string& history)
{
    if (ssn->payload_bytes_seen_client)
        history += "D";
    if (ssn->payload_bytes_seen_server)
        history += "d";
}

const string& EofEvent::get_history() const
{
    history = "";

    if (f->session == nullptr)
        return history;

    if (f->pkt_type == PktType::TCP)
        get_tcp_history((const TcpSession*)f->session, history);
    else if (f->pkt_type == PktType::UDP)
        get_udp_history((const UdpSession*)f->session, history);

    return history;
}

//-------------------------------------------------------------------------
//  State
//-------------------------------------------------------------------------

static void get_udp_state(const Flow* f, string& state)
{
    static const string state_udp_clt = "CLT_UDP_SEEN";
    static const string state_udp_srv = "SRV_UDP_SEEN";
    static const string state_udp_both = "CLT_SRV_UDP_SEEN";

    if (f->flowstats.client_pkts and f->flowstats.server_pkts)
        state = state_udp_both;
    else if (f->flowstats.client_pkts)
        state = state_udp_clt;
    else if (f->flowstats.server_pkts)
        state = state_udp_srv;
}

static void get_tcp_state(const Flow* f, string& state)
{
    const TcpSession* ssn = (TcpSession*) f->session;
    if (ssn == nullptr)
        return;

    static const string client_prefix = "CLT_";
    static const string server_prefix = "SRV_";

    state = client_prefix + tcp_state_names[ssn->client.get_tcp_state()] + " " +
            server_prefix + tcp_state_names[ssn->server.get_tcp_state()];
}

const string& EofEvent::get_state() const
{
    static const string state_oth = "OTH";
    state = state_oth;
  
    if (f->pkt_type == PktType::TCP)
        get_tcp_state(f, state);
    else if (f->pkt_type == PktType::UDP)
        get_udp_state(f, state);

    return state;
}

//-------------------------------------------------------------------------
//  Unit Tests
//-------------------------------------------------------------------------

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

TEST_CASE("coverage", "[eof_event]")
{
    Flow* flow = new Flow;
    InspectionPolicy ins;
    set_inspection_policy(&ins);
    NetworkPolicy net;
    set_network_policy(&net);
    EofEvent eof(flow);

    SECTION("history no ssn")
    {
        const string& history = eof.get_history();
        CHECK(history == "");
    }

    SECTION("tcp state no ssn")
    {
        flow->pkt_type = PktType::TCP;
        const string& state = eof.get_state();
        CHECK(state == "OTH");
    }

    SECTION("udp state OTH")
    {
        flow->pkt_type = PktType::UDP;
        const string& state = eof.get_state();
        CHECK(state == "OTH");
    }

    SECTION("udp state SRV_UDP_SEEN")
    {
        flow->flowstats.server_pkts = 1;
        flow->pkt_type = PktType::UDP;
        const string& state = eof.get_state();
        CHECK(state == "SRV_UDP_SEEN");
    }

    delete flow;
}

#endif

