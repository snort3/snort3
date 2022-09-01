//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "detection/detection_engine.h"
#include "flow/flow_key.h"
#include "flow/ha.h"
#include "flow/session.h"
#include "framework/data_bus.h"
#include "helpers/bitop.h"
#include "main/analyzer.h"
#include "memory/memory_cap.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "sfip/sf_ip.h"
#include "utils/stats.h"
#include "utils/util.h"

using namespace snort;

Flow::Flow()
{
    constexpr size_t offset = offsetof(Flow, key);
    // FIXIT-L need a struct to zero here to make future proof
    memset((uint8_t*)this+offset, 0, sizeof(*this)-offset);
}

Flow::~Flow()
{
    term();
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

void Flow::term()
{
    if ( !session )
        return;

    delete session;
    session = nullptr;

    if ( flow_data )
        free_flow_data();

    if ( mpls_client.length )
        delete[] mpls_client.start;

    if ( mpls_server.length )
        delete[] mpls_server.start;

    if ( bitop )
        delete bitop;

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
        clouseau->rem_ref();

    if ( gadget )
        gadget->rem_ref();

    if (assistant_gadget)
        assistant_gadget->rem_ref();

    if ( data )
        clear_data();

    if ( ha_state )
        delete ha_state;

    if (stash)
    {
        delete stash;
        stash = nullptr;
    }

    service = nullptr;
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
    if ( bitop )
    {
        delete bitop;
        bitop = nullptr;
    }
    filtering_state.clear();
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

    free_flow_data();
    clean();

    // FIXIT-M cleanup() winds up calling clear()
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

    if ( data )
        clear_data();

    if ( ha_state )
        ha_state->reset();

    if ( stash )
        stash->reset();

    deferred_trust.clear();

    constexpr size_t offset = offsetof(Flow, context_chain);
    // FIXIT-L need a struct to zero here to make future proof
    memset((uint8_t*)this+offset, 0, sizeof(Flow)-offset);
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

int Flow::set_flow_data(FlowData* fd)
{
    FlowData* old = get_flow_data(fd->get_id());
    assert(old != fd);

    if (old)
        free_flow_data(old);

    fd->prev = nullptr;
    fd->next = flow_data;

    if ( flow_data )
        flow_data->prev = fd;

    flow_data = fd;
    return 0;
}

FlowData* Flow::get_flow_data(unsigned id) const
{
    FlowData* fd = flow_data;

    while (fd)
    {
        if (fd->get_id() == id)
            return fd;

        fd = fd->next;
    }
    return nullptr;
}

// FIXIT-L: implement doubly linked list with STL to cut down on code we maintain
void Flow::free_flow_data(FlowData* fd)
{
    if ( fd == flow_data )
    {
        flow_data = fd->next;
        if ( flow_data )
            flow_data->prev = nullptr;
    }
    else if ( !fd->next )
    {
        fd->prev->next = nullptr;
    }
    else
    {
        fd->prev->next = fd->next;
        fd->next->prev = fd->prev;
    }
    delete fd;
}

void Flow::free_flow_data(uint32_t proto)
{
    FlowData* fd = get_flow_data(proto);

    if ( fd )
        free_flow_data(fd);
}

void Flow::free_flow_data()
{
    if (!flow_data)
        return;
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
            pkthdr.tenant_id = tenant;
            select_default_policy(pkthdr, sc);
        }
    }

    while (flow_data)
    {
        FlowData* tmp = flow_data;
        flow_data = flow_data->next;
        delete tmp;
    }

    if (ps)
    {
        set_network_policy(np);
        set_inspection_policy(ip);
        set_ips_policy(ipsp);
    }
}

void Flow::call_handlers(Packet* p, bool eof)
{
    FlowData* fd = flow_data;

    while (fd)
    {
        if ( eof )
            fd->handle_eof(p);
        else
            fd->handle_retransmit(p);

        fd = fd->next;
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

void Flow::set_expire(const Packet* p, uint32_t timeout)
{
    expire_time = (uint64_t)p->pkth->ts.tv_sec + timeout;
}

bool Flow::expired(const Packet* p)
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

bool Flow::is_pdu_inorder(uint8_t dir)
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
    DataBus::publish(FLOW_SERVICE_CHANGE_EVENT, pkt);
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
