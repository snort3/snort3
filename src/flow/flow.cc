/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2013-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#include "flow.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/session.h"
#include "ips_options/ips_flowbits.h"
#include "utils/bitop_funcs.h"
#include "utils/util.h"
#include "protocols/decode.h"

unsigned FlowData:: flow_id = 0;

// FIXIT can't inline SO_PUBLIC ctor and dtor in header or we get problems:
// ld: warning: direct access in FlowData::FlowData(unsigned int,
// Inspector*) to global weak symbol vtable for FlowData means the weak
// symbol cannot be overridden at runtime. This was likely caused by
// different translation units being compiled with different visibility
// settings.

SO_PUBLIC FlowData::FlowData(unsigned u, Inspector* ph)
{
    assert(u > 0);
    id = u;  handler = ph;
    if ( handler ) handler->add_ref();
}

SO_PUBLIC FlowData::~FlowData()
{ if ( handler ) handler->rem_ref(); }

Flow::Flow ()
{
    memset(this, 0, sizeof(*this));
}

Flow::Flow (int proto)
{
    memset(this, 0, sizeof(*this));
    protocol = proto;

    // FIXIT getFlowbitSizeInBytes() should be attribute of ???
    /* use giFlowbitSize - 1, since there is already 1 byte in the
    * StreamFlowData structure */
    size_t sz = sizeof(StreamFlowData) + getFlowbitSizeInBytes() - 1;
    flowdata = (StreamFlowData*)SnortAlloc(sz);

    init = true;
}

Flow::~Flow ()
{
    free_application_data();

    if ( flowdata )
        free(flowdata);

    if ( session )
        delete session;
}

void Flow::reset()
{
    if ( !init )
        session->cleanup();

    constexpr size_t offset = offsetof(Flow, appDataList);
    memset((uint8_t*)this+offset, 0, sizeof(Flow)-offset);

    boInitStaticBITOP(
        &(flowdata->boFlowbits), getFlowbitSizeInBytes(), flowdata->flowb);

    init = true;
}

void Flow::clear(bool freeAppData)
{
    if ( freeAppData )
        free_application_data();

    boResetBITOP(&(flowdata->boFlowbits));

    s5_state.ignore_direction = 0;
    s5_state.session_flags = SSNFLAG_NONE;

    session_state = STREAM5_STATE_NONE;
    expire_time = 0;
}

int Flow::set_application_data(FlowData* fd)
{
    FlowData *appData = get_application_data(fd->get_id());
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

void Flow::markup_packet_flags(Packet* p)
{
    if ( (s5_state.session_flags & SSNFLAG_ESTABLISHED) != SSNFLAG_ESTABLISHED )
    {
        if ( (s5_state.session_flags & (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT)) !=
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
    if ( s5_state.session_flags & SSNFLAG_STREAM_ORDER_BAD )
        p->packet_flags |= PKT_STREAM_ORDER_BAD;
}

void Flow::set_direction(Packet* p)
{
    if(IS_IP4(p))
    {
        if (sfip_fast_eq4(&p->ip4h->ip_src, &client_ip))
        {
            if (GET_IPH_PROTO(p) == IPPROTO_TCP)
            {
                if (p->tcph->th_sport == client_port)
                {
                    p->packet_flags |= PKT_FROM_CLIENT;
                }
                else
                {
                    p->packet_flags |= PKT_FROM_SERVER;
                }
            }
            else if (GET_IPH_PROTO(p) == IPPROTO_UDP)
            {
                if (p->udph->uh_sport == client_port)
                {
                    p->packet_flags |= PKT_FROM_CLIENT;
                }
                else
                {
                    p->packet_flags |= PKT_FROM_SERVER;
                }
            }
            else
            {
                p->packet_flags |= PKT_FROM_CLIENT;
            }
        }
        else if (sfip_fast_eq4(&p->ip4h->ip_dst, &client_ip))
        {
            if  (GET_IPH_PROTO(p) == IPPROTO_TCP)
            {
                if (p->tcph->th_dport == client_port)
                {
                    p->packet_flags |= PKT_FROM_SERVER;
                }
                else
                {
                    p->packet_flags |= PKT_FROM_CLIENT;
                }
            }
            else if (GET_IPH_PROTO(p) == IPPROTO_UDP)
            {
                if (p->udph->uh_dport == client_port)
                {
                    p->packet_flags |= PKT_FROM_SERVER;
                }
                else
                {
                    p->packet_flags |= PKT_FROM_CLIENT;
                }
            }
            else
            {
                p->packet_flags |= PKT_FROM_SERVER;
            }
        }
    }
    else /* IS_IP6(p) */
    {
        if (sfip_fast_eq6(&p->ip6h->ip_src, &client_ip))
        {
            if (GET_IPH_PROTO(p) == IPPROTO_TCP)
            {
                if (p->tcph->th_sport == client_port)
                {
                    p->packet_flags |= PKT_FROM_CLIENT;
                }
                else
                {
                    p->packet_flags |= PKT_FROM_SERVER;
                }
            }
            else if (GET_IPH_PROTO(p) == IPPROTO_UDP)
            {
                if (p->udph->uh_sport == client_port)
                {
                    p->packet_flags |= PKT_FROM_CLIENT;
                }
                else
                {
                    p->packet_flags |= PKT_FROM_SERVER;
                }
            }
            else
            {
                p->packet_flags |= PKT_FROM_CLIENT;
            }
        }
        else if (sfip_fast_eq6(&p->ip6h->ip_dst, &client_ip))
        {
            if  (GET_IPH_PROTO(p) == IPPROTO_TCP)
            {
                if (p->tcph->th_dport == client_port)
                {
                    p->packet_flags |= PKT_FROM_SERVER;
                }
                else
                {
                    p->packet_flags |= PKT_FROM_CLIENT;
                }
            }
            else if (GET_IPH_PROTO(p) == IPPROTO_UDP)
            {
                if (p->udph->uh_dport == client_port)
                {
                    p->packet_flags |= PKT_FROM_SERVER;
                }
                else
                {
                    p->packet_flags |= PKT_FROM_CLIENT;
                }
            }
            else
            {
                p->packet_flags |= PKT_FROM_SERVER;
            }
        }
    }
}

static constexpr int TCP_HZ = 100;

static inline uint64_t CalcJiffies(Packet* p)
{
    uint64_t ret = 0;
    uint64_t sec = (uint64_t)p->pkth->ts.tv_sec * TCP_HZ;
    uint64_t usec = (p->pkth->ts.tv_usec / (1000000UL/TCP_HZ));

    ret = sec + usec;

    return ret;
}

void Flow::set_expire(Packet* p, uint32_t timeout)
{
    expire_time = CalcJiffies(p) + (timeout * TCP_HZ);
}

int Flow::get_expire(Packet* p)
{
    return ( CalcJiffies(p) > expire_time );
}

bool Flow::expired(Packet* p)
{
    if ( !expire_time )
        return false;

    uint64_t pkttime = CalcJiffies(p);

    if ( (int)(pkttime - expire_time) > 0 )
        return true;

    return false;
}

void Flow::set_ttl (Packet* p, bool client)
{
    uint8_t inner_ttl = 0, outer_ttl = 0;

    if ( p->outer_iph_api )
        outer_ttl = p->outer_iph_api->iph_ret_ttl(p);

    if ( p->iph_api )
        inner_ttl = p->iph_api->iph_ret_ttl(p);

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

