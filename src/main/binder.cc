/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// binder.cc author Russ Combs <rucombs@cisco.com>

#include "binder.h"
using namespace std;

#include <vector>
#include "flow/flow.h"
#include "framework/inspector.h"
#include "stream/stream_splitter.h"
#include "managers/inspector_manager.h"
#include "protocols/packet.h"
#include "stream/stream_api.h"

static vector<Binding*> bindings;

void Binder::init()
{
}

void Binder::term()
{
    for ( auto* p : bindings )
        delete p;
}

void Binder::add(Binding* b)
{
    bindings.push_back(b);
}

// FIXIT bind this is a temporary hack. note that both ends must be set
// independently and that we must ref count inspectors.
static void set_session(Flow* flow, const char* key)
{
    Inspector* pin = InspectorManager::get_inspector(key);
    flow->set_client(pin);
    flow->set_server(pin);
    flow->clouseau = nullptr;
}

static void set_session(Flow* flow)
{
    flow->ssn_client = nullptr;
    flow->ssn_server = nullptr;
    flow->clouseau = nullptr;
}

// FIXIT use IPPROTO_* directly (any == 0)
static bool check_proto(const Flow* flow, BindProto bp)
{
    switch ( bp )
    {
    case BP_ANY: return true;
    case BP_IP:  return flow->protocol == IPPROTO_IP;
    case BP_ICMP:return flow->protocol == IPPROTO_ICMP;
    case BP_TCP: return flow->protocol == IPPROTO_TCP;
    case BP_UDP: return flow->protocol == IPPROTO_UDP;
    }
    return false;
}

// FIXIT bind services - this is a temporary hack that just looks at ports,
// need to examine all key fields for matching.  ultimately need a routing
// table, scapegoat tree, magic wand, etc.
static Inspector* get_clouseau(Flow* flow, Packet* p)
{
    Binding* pb;
    unsigned i, sz = bindings.size();

    Port port = (p->packet_flags & PKT_FROM_CLIENT) ? p->dp : p->sp;

    for ( i = 0; i < sz; i++ )
    {
        pb = bindings[i];

        if ( !check_proto(flow, pb->proto) )
            continue;

        if ( pb->ports.test(port) )
            break;
    }
    if ( i == sz || !pb->type.size() )
        return nullptr;

    Inspector* ins = InspectorManager::get_inspector(pb->type.c_str());
    return ins;
}

void Binder::init_flow(Flow* flow)
{
    switch ( flow->protocol )
    {
    case IPPROTO_IP:
        set_session(flow, "stream_ip");
        stream.set_splitter(flow, true, nullptr);
        stream.set_splitter(flow, false, nullptr);
        break;

    case IPPROTO_ICMP:
        set_session(flow, "stream_icmp");
        break;

    case IPPROTO_TCP:
        set_session(flow, "stream_tcp");
        break;

    case IPPROTO_UDP:
        set_session(flow, "stream_udp");
        break;

    default:
        set_session(flow);
    }
}

void Binder::init_flow(Flow* flow, Packet* p)
{
    Inspector* ins = get_clouseau(flow, p);

    if ( !ins )
        return;

    if ( flow->protocol == IPPROTO_TCP )
    {
        StreamSplitter* ss = ins->get_splitter(true);
        StreamSplitter* cs = ins->get_splitter(false);

        stream.set_splitter(flow, true, ss);
        stream.set_splitter(flow, false, cs);
    }

    flow->set_clouseau(ins);
}

