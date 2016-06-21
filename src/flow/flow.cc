//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "flow.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/ha.h"
#include "flow/session.h"
#include "ips_options/ips_flowbits.h"
#include "utils/bitop.h"
#include "utils/util.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"

unsigned FlowData::flow_id = 0;

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

Flow::~Flow()
{ }

void Flow::init(PktType type)
{
    pkt_type = type;

    // FIXIT-M getFlowbitSizeInBytes() should be attribute of ??? (or eliminate)
    bitop = new BitOp(getFlowbitSizeInBytes());

    if ( HighAvailabilityManager::active() )
    {
        ha_state = new FlowHAState;
        previous_ssn_state = ssn_state;
    }
}

void Flow::term()
{
    if ( session )
        delete session;

    free_application_data();

    if ( ssn_client )
        ssn_client->rem_ref();

    if ( ssn_server )
        ssn_server->rem_ref();

    if ( clouseau )
        clouseau->rem_ref();

    if ( gadget )
        gadget->rem_ref();

    if ( bitop )
        delete bitop;

    if ( ha_state )
        delete ha_state;
}

void Flow::reset(bool do_cleanup)
{
    if ( session )
    {
        if ( do_cleanup )
            session->cleanup();

        else
            session->clear();
    }

    free_application_data();

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

    constexpr size_t offset = offsetof(Flow, appDataList);
    // FIXIT-L need a struct to zero here to make future proof
    memset((uint8_t*)this+offset, 0, sizeof(Flow)-offset);

    bitop->reset();

    if ( ha_state )
        ha_state->reset();
}

void Flow::restart(bool free_flow_data)
{
    if ( free_flow_data )
        free_application_data();

    bitop->reset();

    ssn_state.ignore_direction = 0;
    ssn_state.session_flags = SSNFLAG_NONE;

    session_state = STREAM_STATE_NONE;
    expire_time = 0;
    previous_ssn_state = ssn_state;
}

void Flow::clear(bool free_flow_data)
{
    restart(free_flow_data);
    set_state(SETUP);

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

int Flow::set_application_data(FlowData* fd)
{
    FlowData* appData = get_application_data(fd->get_id());
    assert(appData != fd);

    if (appData)
        free_application_data(appData);

    fd->prev = nullptr;
    fd->next = appDataList;

    if ( appDataList )
        appDataList->prev = fd;

    appDataList = fd;
    return 0;
}

FlowData* Flow::get_application_data(unsigned id)
{
    FlowData* appData = appDataList;

    while (appData)
    {
        if (appData->get_id() == id)
            return appData;

        appData = appData->next;
    }
    return nullptr;
}

void Flow::free_application_data(FlowData* fd)
{
    if ( fd == appDataList )
    {
        appDataList = fd->next;
        if ( appDataList )
            appDataList->prev = nullptr;
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

void Flow::free_application_data(uint32_t proto)
{
    FlowData* fd = get_application_data(proto);

    if ( fd )
        free_application_data(fd);
}

void Flow::free_application_data()
{
    FlowData* appData = appDataList;

    while (appData)
    {
        FlowData* tmp = appData;
        appData = appData->next;
        delete tmp;
    }
    appDataList = nullptr;
}

void Flow::call_handlers(Packet* p, bool eof)
{
    FlowData* appData = appDataList;

    while (appData)
    {
        if ( eof )
            appData->handle_eof(p);
        else
            appData->handle_retransmit(p);

        appData = appData->next;
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
        if (sfip_fast_eq4(ip_api->get_src(), &client_ip))
        {
            if ( !(p->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP)) )
                p->packet_flags |= PKT_FROM_CLIENT;

            else if (p->ptrs.sp == client_port)
                p->packet_flags |= PKT_FROM_CLIENT;

            else
                p->packet_flags |= PKT_FROM_SERVER;
        }
        else if (sfip_fast_eq4(ip_api->get_dst(), &client_ip))
        {
            if ( !(p->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP)) )
                p->packet_flags |= PKT_FROM_SERVER;

            else if (p->ptrs.dp == client_port)
                p->packet_flags |= PKT_FROM_SERVER;

            else
                p->packet_flags |= PKT_FROM_CLIENT;
        }
    }
    else /* IS_IP6(p) */
    {
        if (sfip_fast_eq6(ip_api->get_src(), &client_ip))
        {
            if ( !(p->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP)) )
                p->packet_flags |= PKT_FROM_CLIENT;

            else if (p->ptrs.sp == client_port)
                p->packet_flags |= PKT_FROM_CLIENT;

            else
                p->packet_flags |= PKT_FROM_SERVER;
        }
        else if (sfip_fast_eq6(ip_api->get_dst(), &client_ip))
        {
            if ( !(p->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP)) )
                p->packet_flags |= PKT_FROM_SERVER;

            else if (p->ptrs.dp == client_port)
                p->packet_flags |= PKT_FROM_SERVER;

            else
                p->packet_flags |= PKT_FROM_CLIENT;
        }
    }
}

static constexpr int TCP_HZ = 100;

static inline uint64_t CalcJiffies(const Packet* p)
{
    uint64_t ret = 0;
    uint64_t sec = (uint64_t)p->pkth->ts.tv_sec * TCP_HZ;
    uint64_t usec = (p->pkth->ts.tv_usec / (1000000UL/TCP_HZ));

    ret = sec + usec;

    return ret;
}

void Flow::set_expire(const Packet* p, uint32_t timeout)
{
    expire_time = CalcJiffies(p) + (timeout * TCP_HZ);
}

int Flow::get_expire(const Packet* p)
{
    return ( CalcJiffies(p) > expire_time );
}

bool Flow::expired(const Packet* p)
{
    if ( !expire_time )
        return false;

    uint64_t pkttime = CalcJiffies(p);

    if ( (int)(pkttime - expire_time) > 0 )
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

