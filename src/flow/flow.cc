//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "flow/ha.h"
#include "flow/session.h"
#include "framework/data_bus.h"
#include "ips_options/ips_flowbits.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"
#include "utils/bitop.h"
#include "utils/stats.h"
#include "utils/util.h"

using namespace snort;

unsigned FlowData::flow_data_id = 0;

FlowData::FlowData(unsigned u, Inspector* ph)
{
    assert(u > 0);
    id = u;
    handler = ph;
    prev = next = nullptr;
    if ( handler )
        handler->add_ref();
}

FlowData::~FlowData()
{
    if ( handler )
        handler->rem_ref();
}

Flow::Flow()
{
    memset(this, 0, sizeof(*this));
}


void Flow::init(PktType type)
{
    pkt_type = type;
    bitop = nullptr;
    flow_flags = 0;

    if ( HighAvailabilityManager::active() )
    {
        ha_state = new FlowHAState;
        previous_ssn_state = ssn_state;
    }
    mpls_client.length = 0;
    mpls_server.length = 0;
}

void Flow::term()
{
    if ( session )
        delete session;

    free_flow_data();

    if ( mpls_client.length )
        delete[] mpls_client.start;

    if ( mpls_server.length )
        delete[] mpls_server.start;

    if ( bitop )
        delete bitop;

    if ( ssn_client )
        ssn_client->rem_ref();

    if ( ssn_server )
        ssn_server->rem_ref();

    if ( clouseau )
        clouseau->rem_ref();

    if ( gadget )
        gadget->rem_ref();

    if ( ha_state )
        delete ha_state;
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
}

void Flow::reset(bool do_cleanup)
{
    DetectionEngine::onload(this);
    DetectionEngine::set_next_packet();
    DetectionEngine de;

    if ( session )
    {
        if ( do_cleanup )
            session->cleanup();

        else
            session->clear();
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

    constexpr size_t offset = offsetof(Flow, flow_data);
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
    FlowData* fd = flow_data;

    while (fd)
    {
        FlowData* tmp = fd;
        fd = fd->next;
        delete tmp;
    }
    flow_data = nullptr;
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
    if ( ssn_state.session_flags & SSNFLAG_STREAM_ORDER_BAD )
        p->packet_flags |= PKT_STREAM_ORDER_BAD;
}

void Flow::set_direction(Packet* p)
{
    ip::IpApi* ip_api = &p->ptrs.ip_api;

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

void Flow::set_service(Packet* pkt, const char* new_service)
{   
    service = new_service;
    DataBus::publish(FLOW_SERVICE_CHANGE_EVENT, pkt);
}   

