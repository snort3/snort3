//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/data_bus.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/stream.h"
#include "stream/tcp/tcp_ha.h"

using namespace snort;

TcpStreamSession::TcpStreamSession(Flow* f)
    : Session(f), client(true), server(false)
{ }

TcpStreamSession::~TcpStreamSession() = default;

void TcpStreamSession::init_new_tcp_session(TcpSegmentDescriptor& tsd)
{
    Packet* p = tsd.get_pkt();

    flow->pkt_type = p->type();
    flow->ip_proto = (uint8_t)p->get_ip_proto_next();

    /* New session, previous was marked as reset.  Clear the reset flag. */
    flow->clear_session_flags(SSNFLAG_RESET);

    flow->set_expire(p, flow->default_session_timeout);

    update_perf_base_state(TcpStreamTracker::TCP_SYN_SENT);

    tcp_init = true;
    lws_init = true;
}

void TcpStreamSession::update_session_on_server_packet(TcpSegmentDescriptor& tsd)
{
    flow->set_session_flags(SSNFLAG_SEEN_SERVER);
    tsd.set_talker(server);
    tsd.set_listener(client);

    if ( !flow->inner_server_ttl && !tsd.is_meta_ack_packet() )
        flow->set_ttl(tsd.get_pkt(), false);
}

void TcpStreamSession::update_session_on_client_packet(TcpSegmentDescriptor& tsd)
{
    /* if we got here we have seen the SYN already... */
    flow->set_session_flags(SSNFLAG_SEEN_CLIENT);
    tsd.set_talker(client);
    tsd.set_listener(server);

    if ( !flow->inner_client_ttl && !tsd.is_meta_ack_packet() )
        flow->set_ttl(tsd.get_pkt(), true);
}

bool TcpStreamSession::can_set_no_ack()
{
    return ( server.get_flush_policy() == STREAM_FLPOLICY_ON_DATA and
         client.get_flush_policy() == STREAM_FLPOLICY_ON_DATA );
}

bool TcpStreamSession::set_no_ack(bool b)
{
    if ( can_set_no_ack() )
    {
        no_ack = b;
        return true;
    }
    else
        return false;
}

void TcpStreamSession::disable_reassembly(Flow* f)
{
    client.set_splitter((StreamSplitter*)nullptr);
    server.set_splitter((StreamSplitter*)nullptr);

    client.reassembler.purge_segment_list();
    server.reassembler.purge_segment_list();

    client.set_flush_policy(STREAM_FLPOLICY_IGNORE);
    server.set_flush_policy(STREAM_FLPOLICY_IGNORE);

    client.finalize_held_packet(f);
    server.finalize_held_packet(f);
}

uint8_t TcpStreamSession::get_reassembly_direction()
{
    uint8_t dir = SSN_DIR_NONE;

    if ( server.get_flush_policy() != STREAM_FLPOLICY_IGNORE )
        dir |= SSN_DIR_FROM_CLIENT;

    if ( client.get_flush_policy() != STREAM_FLPOLICY_IGNORE )
        dir |= SSN_DIR_FROM_SERVER;

    return dir;
}

bool TcpStreamSession::is_sequenced(uint8_t dir)
{
    if ( dir & SSN_DIR_FROM_CLIENT )
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
    if ( dir & SSN_DIR_FROM_CLIENT )
    {
        if ( (server.get_tf_flags() & TF_MISSING_PKT)
            && (server.get_tf_flags() & TF_MISSING_PREV_PKT) )
            return SSN_MISSING_BOTH;
        else if ( server.get_tf_flags() & TF_MISSING_PREV_PKT )
            return SSN_MISSING_BEFORE;
        else if ( server.get_tf_flags() & TF_MISSING_PKT )
            return SSN_MISSING_AFTER;
    }
    else if ( dir & SSN_DIR_FROM_SERVER )
    {
        if ( (client.get_tf_flags() & TF_MISSING_PKT)
            && (client.get_tf_flags() & TF_MISSING_PREV_PKT) )
            return SSN_MISSING_BOTH;
        else if ( client.get_tf_flags() & TF_MISSING_PREV_PKT )
            return SSN_MISSING_BEFORE;
        else if ( client.get_tf_flags() & TF_MISSING_PKT )
            return SSN_MISSING_AFTER;
    }

    return SSN_MISSING_NONE;
}

bool TcpStreamSession::are_packets_missing(uint8_t dir)
{
    if ( dir & SSN_DIR_FROM_CLIENT )
    {
        if ( server.get_tf_flags() & TF_PKT_MISSED )
            return true;
    }

    if ( dir & SSN_DIR_FROM_SERVER )
    {
        if ( client.get_tf_flags() & TF_PKT_MISSED )
            return true;
    }

    return false;
}

bool TcpStreamSession::are_client_segments_queued()
{
    return client.reassembler.is_segment_pending_flush();
}

bool TcpStreamSession::add_alert(Packet* p, uint32_t gid, uint32_t sid)
{
    TcpReassemblerPolicy& trp = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ?
        server.reassembler : client.reassembler;

    return trp.add_alert(gid, sid);
}

bool TcpStreamSession::check_alerted(Packet* p, uint32_t gid, uint32_t sid)
{
    // only check for alert on wire packet if this when processing a rebuilt packet
    if ( !(p->packet_flags & PKT_REBUILT_STREAM) )
        return false;

    TcpReassemblerPolicy& trp = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ?
        server.reassembler : client.reassembler;

    return trp.check_alerted(gid, sid);
}

int TcpStreamSession::update_alert(Packet* p, uint32_t gid, uint32_t sid,
    uint32_t event_id, uint32_t event_second)
{
    TcpReassemblerPolicy& trp = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ?
        server.reassembler : client.reassembler;

    return trp.update_alert(gid, sid, event_id, event_second);
}

bool TcpStreamSession::set_packet_action_to_hold(Packet* p)
{
    if ( p->is_from_client() )
    {
        held_packet_dir = SSN_DIR_FROM_CLIENT;
        return server.set_held_packet(p);
    }
    else
    {
        held_packet_dir = SSN_DIR_FROM_SERVER;
        return client.set_held_packet(p);
    }
}

void TcpStreamSession::set_packet_header_foo(const TcpSegmentDescriptor& tsd)
{
    const Packet* p = tsd.get_pkt();

    if ( tsd.is_packet_from_client() || (p->pkth->egress_index == DAQ_PKTHDR_UNKNOWN
         && p->pkth->egress_group == DAQ_PKTHDR_UNKNOWN) )
    {
        ingress_index = p->pkth->ingress_index;
        ingress_group = p->pkth->ingress_group;
        // ssn egress may be unknown, but will be correct
        egress_index = p->pkth->egress_index;
        egress_group = p->pkth->egress_group;
    }
    else
    {
        egress_index = p->pkth->ingress_index;
        egress_group = p->pkth->ingress_group;
        ingress_index = p->pkth->egress_index;
        ingress_group = p->pkth->egress_group;
    }

    daq_flags = p->pkth->flags;
    address_space_id = p->pkth->address_space_id;
}

void TcpStreamSession::get_packet_header_foo(DAQ_PktHdr_t* pkth, const DAQ_PktHdr_t* orig, uint32_t dir)
{
    if ( (dir & PKT_FROM_CLIENT) || (egress_index == DAQ_PKTHDR_UNKNOWN &&
         egress_group == DAQ_PKTHDR_UNKNOWN) )
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
    pkth->tenant_id = orig->tenant_id;
}

void TcpStreamSession::reset()
{
    if ( tcp_init )
        clear_session(true, false, false );
}

void TcpStreamSession::cleanup(Packet* p)
{
    if ( cleaning )
        return;

    cleaning = true;
    clear_session(true, true, false, p);
    client.normalizer.reset();
    server.normalizer.reset();
    client.reassembler.reset();
    server.reassembler.reset();
    cleaning = false;
}

void TcpStreamSession::clear()
{
    if ( tcp_init )
        clear_session( true, false, false );

    TcpHAManager::process_deletion(*flow);
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
{ tcp_config->policy = StreamPolicy::OS_PROXY; }

void TcpStreamSession::set_established(const TcpSegmentDescriptor& tsd)
{
    update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    flow->session_state |= STREAM_STATE_ESTABLISHED;
    if (SSNFLAG_ESTABLISHED != (SSNFLAG_ESTABLISHED & flow->get_session_flags()))
    {
        flow->set_session_flags(SSNFLAG_ESTABLISHED);
        // Only send 1 event
        if (SSNFLAG_TCP_PSEUDO_EST != (SSNFLAG_TCP_PSEUDO_EST & flow->get_session_flags()))
            DataBus::publish(Stream::get_pub_id(), StreamEventIds::TCP_ESTABLISHED, tsd.get_pkt());
    }
}

void TcpStreamSession::set_pseudo_established(Packet* p)
{
    p->flow->ssn_state.session_flags |= SSNFLAG_TCP_PSEUDO_EST;
    DataBus::publish(Stream::get_pub_id(), StreamEventIds::TCP_ESTABLISHED, p);
}

bool TcpStreamSession::check_for_one_sided_session(Packet* p)
{
    Flow& flow = *p->flow;
    if ( 0 == ( (SSNFLAG_ESTABLISHED | SSNFLAG_TCP_PSEUDO_EST) & flow.ssn_state.session_flags )
        && p->is_from_client_originally() )
    {
        uint64_t initiator_packets;
        uint64_t responder_packets;
        if (flow.flags.client_initiated)
        {
            initiator_packets = flow.flowstats.client_pkts;
            responder_packets = flow.flowstats.server_pkts;
        }
        else
        {
            initiator_packets = flow.flowstats.server_pkts;
            responder_packets = flow.flowstats.client_pkts;
        }

        if ( !responder_packets )
        {
            // handle case where traffic is only in one direction, but the sequence numbers
            // are changing indicating an asynchronous session
            uint32_t watermark = p->ptrs.tcph->seq() + p->ptrs.tcph->ack();
            if ( 1 == initiator_packets )
                initiator_watermark = watermark;
            else if ( initiator_watermark != watermark )
            {
                set_pseudo_established(p);
                return true;
            }
        }
    }
    return false;
}

void TcpStreamSession::check_for_pseudo_established(Packet* p)
{
    Flow& flow = *p->flow;
    if ( 0 == ( (SSNFLAG_ESTABLISHED | SSNFLAG_TCP_PSEUDO_EST) & flow.ssn_state.session_flags ) )
    {
        if ( check_for_one_sided_session(p) )
            return;
        if ( 0 < flow.flowstats.client_pkts && 0 < flow.flowstats.server_pkts )
            set_pseudo_established(p);
    }
}

