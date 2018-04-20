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

// tcp_stream_session.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Feb 18, 2016

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_stream_session.h"

#include "log/messages.h"
#include "stream/tcp/tcp_ha.h"

using namespace snort;

#ifdef DEBUG_MSGS
const char* const flush_policy_names[] =
{
    "ignore",
    "on-ack",
    "on-data"
};
#endif

TcpStreamSession::TcpStreamSession(Flow* f)
    : Session(f), client(true), server(false)
{ }

TcpStreamSession::~TcpStreamSession()
{ }

void TcpStreamSession::init_new_tcp_session(TcpSegmentDescriptor& tsd)
{
    flow->pkt_type = tsd.get_pkt()->type();
    flow->ip_proto = (uint8_t)tsd.get_pkt()->get_ip_proto_next();

    /* New session, previous was marked as reset.  Clear the reset flag. */
    flow->clear_session_flags(SSNFLAG_RESET);
    flow->set_expire(tsd.get_pkt(), config->session_timeout);

    update_perf_base_state(TcpStreamTracker::TCP_SYN_SENT);

    tcp_init = true;
    lws_init = true;
}

void TcpStreamSession::update_session_on_syn_ack()
{
    /* If session is already marked as established */
    if ( !( flow->session_state & STREAM_STATE_ESTABLISHED ) )
    {
        /* SYN-ACK from server */
        if (flow->session_state != STREAM_STATE_NONE)
        {
            flow->session_state |= STREAM_STATE_SYN_ACK;
            update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }
}

void TcpStreamSession::update_session_on_ack()
{
    /* If session is already marked as established */
    if ( !( flow->session_state & STREAM_STATE_ESTABLISHED ) )
    {
        if ( flow->session_state & STREAM_STATE_SYN_ACK )
        {
            flow->session_state |= STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED;
            update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }
}

void TcpStreamSession::update_session_on_server_packet(TcpSegmentDescriptor& tsd)
{
    flow->set_session_flags(SSNFLAG_SEEN_SERVER);
    talker = &server;
    listener = &client;

    /* If we picked this guy up midstream, finish the initialization */
    if ( !( flow->session_state & STREAM_STATE_ESTABLISHED )
        && ( flow->session_state & STREAM_STATE_MIDSTREAM ) )
    {
        if (tsd.get_tcph()->are_flags_set(TH_ECE)
            && (flow->get_session_flags() & SSNFLAG_ECN_CLIENT_QUERY))
            flow->set_session_flags(SSNFLAG_ECN_SERVER_REPLY);

        if (flow->get_session_flags() & SSNFLAG_SEEN_CLIENT)
        {
            // should TCP state go to established too?
            flow->session_state |= STREAM_STATE_ESTABLISHED;
            flow->set_session_flags(SSNFLAG_ESTABLISHED);
            update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }

    if (!flow->inner_server_ttl)
        flow->set_ttl(tsd.get_pkt(), false);
}

void TcpStreamSession::update_session_on_client_packet(TcpSegmentDescriptor& tsd)
{
    /* if we got here we had to see the SYN already... */
    flow->set_session_flags(SSNFLAG_SEEN_CLIENT);
    talker = &client;
    listener = &server;

    if ( !( flow->session_state & STREAM_STATE_ESTABLISHED )
        && ( flow->session_state & STREAM_STATE_MIDSTREAM ) )
    {
        /* Midstream and seen server. */
        if (flow->get_session_flags() & SSNFLAG_SEEN_SERVER)
        {
            flow->session_state |= STREAM_STATE_ESTABLISHED;
            flow->set_session_flags(SSNFLAG_ESTABLISHED);
        }
    }

    if (!flow->inner_client_ttl)
        flow->set_ttl(tsd.get_pkt(), true);
}

uint8_t TcpStreamSession::get_reassembly_direction()
{
    uint8_t dir = SSN_DIR_NONE;

    if (server.get_flush_policy() != STREAM_FLPOLICY_IGNORE)
        dir |= SSN_DIR_FROM_CLIENT;

    if (client.get_flush_policy() != STREAM_FLPOLICY_IGNORE)
        dir |= SSN_DIR_FROM_SERVER;

    return dir;
}

bool TcpStreamSession::is_sequenced(uint8_t dir)
{
    if (dir & SSN_DIR_FROM_CLIENT)
    {
        if ( server.get_tf_flags() & ( TF_MISSING_PREV_PKT | TF_PKT_MISSED ) )
            return false;
    }

    if ( dir & SSN_DIR_FROM_SERVER )
    {
        if ( client.get_tf_flags() & ( TF_MISSING_PREV_PKT | TF_PKT_MISSED ) )
            return false;
    }

    return true;
}

/* This will falsely return SSN_MISSING_BEFORE on the first reassembled
 * packet if reassembly for this direction was set mid-session */
uint8_t TcpStreamSession::missing_in_reassembled(uint8_t dir)
{
    if (dir & SSN_DIR_FROM_CLIENT)
    {
        if ( (server.get_tf_flags() & TF_MISSING_PKT)
            && (server.get_tf_flags() & TF_MISSING_PREV_PKT))
            return SSN_MISSING_BOTH;
        else if (server.get_tf_flags() & TF_MISSING_PREV_PKT)
            return SSN_MISSING_BEFORE;
        else if (server.get_tf_flags() & TF_MISSING_PKT)
            return SSN_MISSING_AFTER;
    }
    else if (dir & SSN_DIR_FROM_SERVER)
    {
        if ((client.get_tf_flags() & TF_MISSING_PKT)
            && (client.get_tf_flags() & TF_MISSING_PREV_PKT))
            return SSN_MISSING_BOTH;
        else if (client.get_tf_flags() & TF_MISSING_PREV_PKT)
            return SSN_MISSING_BEFORE;
        else if (client.get_tf_flags() & TF_MISSING_PKT)
            return SSN_MISSING_AFTER;
    }

    return SSN_MISSING_NONE;
}

bool TcpStreamSession::are_packets_missing(uint8_t dir)
{
    if (dir & SSN_DIR_FROM_CLIENT)
    {
        if (server.get_tf_flags() & TF_PKT_MISSED)
            return true;
    }

    if (dir & SSN_DIR_FROM_SERVER)
    {
        if (client.get_tf_flags() & TF_PKT_MISSED)
            return true;
    }

    return false;
}

void TcpStreamSession::update_direction(char dir, const SfIp* ip, uint16_t port)
{
    SfIp tmpIp;
    uint16_t tmpPort;

    if (flow->client_ip.equals(*ip) && (flow->client_port == port))
    {
        if ((dir == SSN_DIR_FROM_CLIENT) && (flow->ssn_state.direction == FROM_CLIENT))
        {
            /* Direction already set as client */
            return;
        }
    }
    else if (flow->server_ip.equals(*ip) && (flow->server_port == port))
    {
        if ((dir == SSN_DIR_FROM_SERVER) && (flow->ssn_state.direction == FROM_SERVER))
        {
            /* Direction already set as server */
            return;
        }
    }

    /* Swap them -- leave flow->ssn_state.direction the same */
    tmpIp = flow->client_ip;
    tmpPort = flow->client_port;
    flow->client_ip = flow->server_ip;
    flow->client_port = flow->server_port;
    flow->server_ip = tmpIp;
    flow->server_port = tmpPort;

    SwapPacketHeaderFoo( );
    TcpStreamTracker& tracker = client;
    client = server;
    server = tracker;
}

// FIXIT-H add alert and check alerted go away when we finish
// packet / PDU split because PDU rules won't run on raw packets
bool TcpStreamSession::add_alert(Packet* p, uint32_t gid, uint32_t sid)
{
    TcpStreamTracker& st = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ? server : client;
    StreamAlertInfo* ai;

    if (st.alert_count >= MAX_SESSION_ALERTS)
        return false;

    ai = st.alerts + st.alert_count;
    ai->gid = gid;
    ai->sid = sid;
    ai->seq = 0;
    ai->event_id = 0;
    ai->event_second = 0;

    st.alert_count++;

    return true;
}

bool TcpStreamSession::check_alerted(Packet* p, uint32_t gid, uint32_t sid)
{
    /* If this is not a rebuilt packet, no need to check further */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return false;

    TcpStreamTracker& st = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ? server : client;
    for (int i = 0; i < st.alert_count; i++)
    {
        /*  This is a rebuilt packet and if we've seen this alert before,
         *  return that we have previously alerted on original packet.
         */
        if (st.alerts[i].gid == gid && st.alerts[i].sid == sid)
            return true;
    }

    return false;
}

int TcpStreamSession::update_alert(Packet* p, uint32_t gid, uint32_t sid,
    uint32_t event_id, uint32_t event_second)
{
    uint32_t seq_num = 0;
    TcpStreamTracker& st = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ? server : client;

    for (unsigned i = 0; i < st.alert_count; i++)
    {
        StreamAlertInfo* ai = st.alerts + i;

        if (ai->gid == gid && ai->sid == sid && SEQ_EQ(ai->seq, seq_num))
        {
            ai->event_id = event_id;
            ai->event_second = event_second;
            return 0;
        }
    }

    return -1;
}

void TcpStreamSession::SetPacketHeaderFoo(const Packet* p)
{
    if ( daq_flags & DAQ_PKT_FLAG_NOT_FORWARDING )
    {
        ingress_index = p->pkth->ingress_index;
        ingress_group = p->pkth->ingress_group;
        // ssn egress may be unknown, but will be correct
        egress_index = p->pkth->egress_index;
        egress_group = p->pkth->egress_group;
    }
    else if ( p->is_from_client() )
    {
        ingress_index = p->pkth->ingress_index;
        ingress_group = p->pkth->ingress_group;
        // ssn egress not always correct here
    }
    else
    {
        // ssn ingress not always correct here
        egress_index = p->pkth->ingress_index;
        egress_group = p->pkth->ingress_group;
    }
    daq_flags = p->pkth->flags;
    address_space_id = p->pkth->address_space_id;
    if (daq_flags & DAQ_PKT_FLAG_REAL_ADDRESSES)
    {
        memcpy(real_src_ip.u6_addr8, &p->pkth->real_sIP, sizeof(ip::snort_in6_addr));
        memcpy(real_dst_ip.u6_addr8, &p->pkth->real_dIP, sizeof(ip::snort_in6_addr));
        real_src_port = p->pkth->n_real_sPort;
        real_dst_port = p->pkth->n_real_dPort;
    }
}

void TcpStreamSession::GetPacketHeaderFoo(DAQ_PktHdr_t* pkth, uint32_t dir)
{
    if ( (dir & PKT_FROM_CLIENT) || (daq_flags & DAQ_PKT_FLAG_NOT_FORWARDING) )
    {
        pkth->ingress_index = ingress_index;
        pkth->ingress_group = ingress_group;
        pkth->egress_index = egress_index;
        pkth->egress_group = egress_group;
    }
    else
    {
        pkth->ingress_index = egress_index;
        pkth->ingress_group = egress_group;
        pkth->egress_index = ingress_index;
        pkth->egress_group = ingress_group;
    }
    pkth->opaque = 0;
    pkth->flags = daq_flags;
    pkth->address_space_id = address_space_id;
    if (daq_flags & DAQ_PKT_FLAG_REAL_ADDRESSES)
    {
        memcpy(&pkth->real_sIP, real_src_ip.u6_addr8, sizeof(ip::snort_in6_addr));
        memcpy(&pkth->real_dIP, real_dst_ip.u6_addr8, sizeof(ip::snort_in6_addr));
        pkth->n_real_sPort = real_src_port;
        pkth->n_real_dPort = real_dst_port;
    }
}

void TcpStreamSession::SwapPacketHeaderFoo()
{
    if ( egress_index != DAQ_PKTHDR_UNKNOWN )
    {
        int32_t save_ingress_index;
        int32_t save_ingress_group;

        save_ingress_index = ingress_index;
        save_ingress_group = ingress_group;
        ingress_index = egress_index;
        ingress_group = egress_group;
        egress_index = save_ingress_index;
        egress_group = save_ingress_group;
    }
}

void TcpStreamSession::reset()
{
    if (tcp_init)
        clear_session(true, false, false );
}

bool TcpStreamSession::setup(Packet*)
{
    client.init_tcp_state();
    server.init_tcp_state();
    lws_init = tcp_init = false;
    generate_3whs_alert = true;
    pkt_action_mask = ACTION_NOTHING;
    ecn = 0;
    ingress_index = egress_index = 0;
    ingress_group = egress_group = 0;
    daq_flags = address_space_id = 0;
    config = nullptr;

    return true;
}

void TcpStreamSession::cleanup(Packet* p)
{
    clear_session(true, true, false, p);
    client.normalizer.reset();
    server.reassembler.reset();
}

void TcpStreamSession::clear()
{
    if ( tcp_init )
        // this does NOT flush data
        clear_session( true, false, false );

    TcpHAManager::process_deletion(flow);
}

void TcpStreamSession::set_splitter(bool to_server, StreamSplitter* ss)
{
    TcpStreamTracker& trk = ( to_server ) ? server : client;

    trk.set_splitter(ss);
}

uint16_t TcpStreamSession::get_mss(bool to_server) const
{
    const TcpStreamTracker& trk = (to_server) ? client : server;

    return trk.get_mss();
}

uint8_t TcpStreamSession::get_tcp_options_len(bool to_server) const
{
    const TcpStreamTracker& trk = (to_server) ? client : server;

    return trk.get_tcp_options_len();
}

StreamSplitter* TcpStreamSession::get_splitter(bool to_server)
{
    if ( to_server )
        return server.get_splitter();
    else
        return client.get_splitter();
}

void TcpStreamSession::start_proxy()
{
    config->policy = StreamPolicy::OS_PROXY;
}

//-------------------------------------------------------------------------
// tcp module stuff
//-------------------------------------------------------------------------

void TcpStreamSession::sinit()
{
    //AtomSplitter::init();  // FIXIT-L PAF implement
}

void TcpStreamSession::sterm()
{ }

void TcpStreamSession::print()
{
    char buf[64];

    LogMessage("TcpStreamSession:\n");
    sfip_ntop(&flow->server_ip, buf, sizeof(buf));
    LogMessage("    server IP:          %s\n", buf);
    sfip_ntop(&flow->client_ip, buf, sizeof(buf));
    LogMessage("    client IP:          %s\n", buf);
    LogMessage("    server port:        %d\n", flow->server_port);
    LogMessage("    client port:        %d\n", flow->client_port);
    LogMessage("    flags:              0x%X\n", flow->get_session_flags());
    LogMessage("Client Tracker:\n");
    client.print();
    LogMessage("Server Tracker:\n");
    server.print();
}


