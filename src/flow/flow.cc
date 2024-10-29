//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow.h"

#include "detection/context_switcher.h"
#include "detection/detection_continuation.h"
#include "detection/detection_engine.h"
#include "flow/flow_control.h"
#include "flow/flow_key.h"
#include "flow/ha.h"
#include "flow/session.h"
#include "framework/data_bus.h"
#include "helpers/bitop.h"
#include "main/analyzer.h"
#include "packet_io/packet_tracer.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"
#include "time/clock_defs.h"
#include "utils/stats.h"
#include "utils/util.h"

using namespace snort;
extern THREAD_LOCAL class FlowControl* flow_con;

Flow::~Flow()
{
    free_flow_data();
    delete session;

    if ( mpls_client.length )
        delete[] mpls_client.start;
    if ( mpls_server.length )
        delete[] mpls_server.start;
    delete bitop;

    if ( ssn_client )
        ssn_client->rem_ref();

    if ( ssn_server )
        ssn_server->rem_ref();

    if ( clouseau )
        clouseau->rem_ref();

    if ( gadget )
        gadget->rem_ref();

    if (assistant_gadget)
        assistant_gadget->rem_ref();

    if ( data )
        clear_data();

    delete ha_state;
    delete stash;
    delete ips_cont;
}

void Flow::init(PktType type)
{
    pkt_type = type;
    bitop = nullptr;

    if ( HighAvailabilityManager::active() )
    {
        ha_state = new FlowHAState;
        previous_ssn_state = ssn_state;
    }
    mpls_client.length = 0;
    mpls_server.length = 0;

    stash = new FlowStash;
}

inline void Flow::clean()
{
    if ( mpls_client.length )
    {
        delete[] mpls_client.start;
        mpls_client.length = 0;
    }
    if ( mpls_server.length )
    {
        delete[] mpls_server.start;
        mpls_server.length = 0;
    }
    delete bitop;
    bitop = nullptr;
    filtering_state.clear();

    inspected_packet_count = 0;
    inspection_duration = 0;
}

void Flow::flush(bool do_cleanup)
{
    if ( session )
    {
        DetectionEngine::onload(this);

        if ( !do_cleanup )
            session->clear();

        else if ( Analyzer::get_switcher()->get_context() )
            session->flush();

        else
        {
            DetectionEngine::set_next_packet();
            DetectionEngine de;
            session->flush();
        }
    }

    if ( was_blocked() )
        free_flow_data();
}

void Flow::reset(bool do_cleanup)
{
    if ( session )
    {
        DetectionEngine::onload(this);

        if ( !do_cleanup )
            session->clear();

        else if ( Analyzer::get_switcher()->get_context() )
            session->cleanup();

        else
        {
            DetectionEngine::set_next_packet();
            DetectionEngine de;
            session->cleanup();
        }
    }
}

void Flow::restart(bool dump_flow_data)
{
    DetectionEngine::onload(this);

    if ( dump_flow_data )
        free_flow_data();

    clean();

    ssn_state.ignore_direction = 0;
    ssn_state.session_flags = SSNFLAG_NONE;

    session_state = STREAM_STATE_NONE;
    expire_time = 0;
    previous_ssn_state = ssn_state;
}

void Flow::clear(bool dump_flow_data)
{
    restart(dump_flow_data);
    set_state(FlowState::SETUP);

    if ( ssn_client )
    {
        ssn_client->rem_ref();
        ssn_client = nullptr;
    }
    if ( ssn_server )
    {
        ssn_server->rem_ref();
        ssn_server = nullptr;
    }
    if ( clouseau )
        clear_clouseau();

    if ( gadget )
        clear_gadget();
}

void Flow::trust()
{
    set_ignore_direction(SSN_DIR_BOTH);
    set_state(Flow::FlowState::ALLOW);
    disable_inspection();
}

uint64_t Flow::fetch_add_inspection_duration()
{
    if (inspected_packet_count != 0)
        return get_inspection_duration();

    auto c = DetectionEngine::get_context();

    if (c and c->packet and c->packet->inspection_started_timestamp)
    {
        auto packet = c->packet;
        const auto timestamp = TO_USECS_FROM_EPOCH(SnortClock::now());

        add_inspection_duration(timestamp - packet->inspection_started_timestamp);
        packet->inspection_started_timestamp = timestamp;
    }

    return get_inspection_duration();
}

int Flow::set_flow_data(FlowData* fd)
{
    if ( !fd ) return -1;

    current_flow_data = fd;
    uint32_t id = fd->get_id();
    // operator[] will create a new entry if it does not exist
    // or replace the existing one if it does
    // when replacing, the old entry is deleted
    flow_data[id] = std::unique_ptr<FlowData>(fd);
    return 0;
}


FlowData* Flow::get_flow_data(unsigned id) const
{
    auto it = flow_data.find(id);
    if ( it != flow_data.end() )
        return it->second.get();
    return nullptr;
}

void Flow::free_flow_data(FlowData* fd)
{
    if ( fd )
        flow_data.erase(fd->get_id());
}

void Flow::free_flow_data(uint32_t proto)
{
    flow_data.erase(proto);
}

void Flow::free_flow_data()
{
    if ( flow_data.empty() )
    {
        if (stash)
            stash->reset();
        return;
    }
    const SnortConfig* sc = SnortConfig::get_conf();
    PolicySelector* ps = sc->policy_map->get_policy_selector();
    NetworkPolicy* np = nullptr;
    InspectionPolicy* ip = nullptr;
    IpsPolicy* ipsp = nullptr;
    if (ps)
    {
        np = get_network_policy();
        ip = get_inspection_policy();
        ipsp = get_ips_policy();

        unsigned t_reload_id = SnortConfig::get_thread_reload_id();
        if (reload_id == t_reload_id)
        {
            ::set_network_policy(network_policy_id);
            ::set_inspection_policy(inspection_policy_id);
            ::set_ips_policy(sc, ips_policy_id);
        }
        else
        {
            _daq_pkt_hdr pkthdr = {};
            pkthdr.address_space_id = key->addressSpaceId;
#ifndef DISABLE_TENANT_ID
            pkthdr.tenant_id = key->tenant_id;
#else
            pkthdr.tenant_id = 0;
#endif
            select_default_policy(pkthdr, sc);
        }
    }

    flow_data.clear();
    if (stash)
        stash->reset();

    if (ps)
    {
        set_network_policy(np);
        set_inspection_policy(ip);
        set_ips_policy(ipsp);
    }
}

void Flow::call_handlers(Packet* p, bool eof)
{
    for (auto& fd_pair : flow_data)
    {
        FlowData* fd = fd_pair.second.get();
        if ( eof )
            fd->handle_eof(p);
        else
            fd->handle_retransmit(p);
    }
}

void Flow::markup_packet_flags(Packet* p)
{
    if ( (ssn_state.session_flags & SSNFLAG_ESTABLISHED) != SSNFLAG_ESTABLISHED )
    {
        if ( (ssn_state.session_flags & (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT)) !=
            (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT) )
        {
            p->packet_flags |= PKT_STREAM_UNEST_UNI;
        }
        if ( (ssn_state.session_flags & SSNFLAG_TCP_PSEUDO_EST) == SSNFLAG_TCP_PSEUDO_EST )
        {
            p->packet_flags |= PKT_TCP_PSEUDO_EST;
        }
    }
    else
    {
        p->packet_flags |= PKT_STREAM_EST;

        if ( p->packet_flags & PKT_STREAM_UNEST_UNI )
            p->packet_flags ^= PKT_STREAM_UNEST_UNI;
    }
}

void Flow::set_client_initiate(Packet* p)
{
    if (p->pkth->flags & DAQ_PKT_FLAG_REV_FLOW)
        flags.client_initiated = p->is_from_server();
    // If we are tracking on syn, client initiated follows from client
    else if (p->context->conf->track_on_syn())
        flags.client_initiated = p->is_from_client();
    // If not tracking on SYN and the packet is a SYN-ACK, assume the SYN did not create a
    // session and client initiated follows from server
    else if (p->is_tcp() and p->ptrs.tcph->is_syn_ack())
        flags.client_initiated = p->is_from_server();
    // Otherwise, client initiated follows from client
    else
        flags.client_initiated = p->is_from_client();
}

void Flow::set_direction(Packet* p)
{
    ip::IpApi* ip_api = &p->ptrs.ip_api;

    // FIXIT-M This does not work properly for NAT "real" v6 addresses on top of v4 packet data
    //  (it will only compare a portion of the address)
    if (ip_api->is_ip4())
    {
        if (ip_api->get_src()->fast_eq4(client_ip))
        {
            if ( p->type() != PktType::TCP and p->type() != PktType::UDP )
                p->packet_flags |= PKT_FROM_CLIENT;

            else if (p->ptrs.sp == client_port)
                p->packet_flags |= PKT_FROM_CLIENT;

            else
                p->packet_flags |= PKT_FROM_SERVER;
        }
        else if (ip_api->get_dst()->fast_eq4(client_ip))
        {
            if ( p->type() != PktType::TCP and p->type() != PktType::UDP )
                p->packet_flags |= PKT_FROM_SERVER;

            else if (p->ptrs.dp == client_port)
                p->packet_flags |= PKT_FROM_SERVER;

            else
                p->packet_flags |= PKT_FROM_CLIENT;
        }
    }
    else /* IS_IP6(p) */
    {
        if (ip_api->get_src()->fast_eq6(client_ip))
        {
            if ( p->type() != PktType::TCP and p->type() != PktType::UDP )
                p->packet_flags |= PKT_FROM_CLIENT;

            else if (p->ptrs.sp == client_port)
                p->packet_flags |= PKT_FROM_CLIENT;

            else
                p->packet_flags |= PKT_FROM_SERVER;
        }
        else if (ip_api->get_dst()->fast_eq6(client_ip))
        {
            if ( p->type() != PktType::TCP and p->type() != PktType::UDP )
                p->packet_flags |= PKT_FROM_SERVER;

            else if (p->ptrs.dp == client_port)
                p->packet_flags |= PKT_FROM_SERVER;

            else
                p->packet_flags |= PKT_FROM_CLIENT;
        }
    }
}

void Flow::set_expire(const Packet* p, uint64_t timeout)
{
    expire_time = (uint64_t)p->pkth->ts.tv_sec + timeout;
}

bool Flow::expired(const Packet* p) const
{
    if ( !expire_time )
        return false;

    if ( (uint64_t)p->pkth->ts.tv_sec > expire_time )
        return true;

    return false;
}

void Flow::set_ttl(Packet* p, bool client)
{
    uint8_t inner_ttl = 0, outer_ttl = 0;

    ip::IpApi outer_ip_api;
    int8_t tmp = 0;
    layer::set_outer_ip_api(p, outer_ip_api, tmp);

    /*
     * If there is only one IP layer, then
     * outer_ip == inner_ip ==> both are true.
     *
     * If there are no IP layers, then
     * outer_ip.is_valid() == inner_ip.is_valid() == false
     */
    if (outer_ip_api.is_ip())
    {
        // FIXIT-L do we want more than just the outermost and innermost ttl()?
        outer_ttl = outer_ip_api.ttl();
        inner_ttl = p->ptrs.ip_api.ttl();
    }

    if ( client )
    {
        outer_client_ttl = outer_ttl;
        inner_client_ttl = inner_ttl;
    }
    else
    {
        outer_server_ttl = outer_ttl;
        inner_server_ttl = inner_ttl;
    }
}

void Flow::set_mpls_layer_per_dir(Packet* p)
{
    const Layer* mpls_lyr = layer::get_mpls_layer(p);

    if ( !mpls_lyr || !(mpls_lyr->start) )
        return;

    if ( p->packet_flags & PKT_FROM_CLIENT )
    {
        if ( !mpls_client.length )
        {
            mpls_client.length = mpls_lyr->length;
            mpls_client.prot_id = mpls_lyr->prot_id;
            mpls_client.start = new uint8_t[mpls_lyr->length];
            memcpy((void *)mpls_client.start, mpls_lyr->start, mpls_lyr->length);
        }
    }
    else
    {
        if ( !mpls_server.length )
        {
            mpls_server.length = mpls_lyr->length;
            mpls_server.prot_id = mpls_lyr->prot_id;
            mpls_server.start = new uint8_t[mpls_lyr->length];
            memcpy((void *)mpls_server.start, mpls_lyr->start, mpls_lyr->length);
        }
    }
}

Layer Flow::get_mpls_layer_per_dir(bool client)
{
    if ( client )
        return mpls_client;
    else
        return mpls_server;
}

bool Flow::is_pdu_inorder(uint8_t dir) const
{
    return ( (session != nullptr) && session->is_sequenced(dir)
            && (session->missing_in_reassembled(dir) == SSN_MISSING_NONE)
            && !(ssn_state.session_flags & SSNFLAG_MIDSTREAM));
}

bool Flow::is_direction_aborted(bool from_client) const
{
    const uint32_t session_flags = get_session_flags();

    if (from_client)
        return (session_flags & SSNFLAG_ABORT_SERVER);

    return (session_flags & SSNFLAG_ABORT_CLIENT);
}

void Flow::set_service(Packet* pkt, const char* new_service)
{
    service = new_service;
    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_SERVICE_CHANGE, pkt);
}

void Flow::swap_roles()
{
    std::swap(flowstats.client_pkts, flowstats.server_pkts);
    std::swap(flowstats.client_bytes, flowstats.server_bytes);
    std::swap(mpls_client, mpls_server);
    std::swap(client_ip, server_ip);
    std::swap(client_intf, server_intf);
    std::swap(client_group, server_group);
    std::swap(client_port, server_port);
    std::swap(inner_client_ttl, inner_server_ttl);
    std::swap(outer_client_ttl, outer_server_ttl);
    flags.client_initiated = !flags.client_initiated;
}

bool Flow::handle_allowlist()
{
    if ( flow_con->get_flow_cache_config().allowlist_cache and !flags.in_allowlist )
    {
        if ( flow_con->move_to_allowlist(this) )
        {
            PacketTracer::log("Flow: flow has been moved to allowlist cache\n");
            return true;
        }
    }
    return false;
}
