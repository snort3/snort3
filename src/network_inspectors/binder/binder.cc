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

#include <vector>
using namespace std;

#include "binding.h"
#include "bind_module.h"
#include "flow/flow.h"
#include "framework/inspector.h"
#include "stream/stream_splitter.h"
#include "managers/inspector_manager.h"
#include "protocols/packet.h"
#include "protocols/vlan.h"
#include "protocols/layer.h"
#include "stream/stream_api.h"
#include "time/profiler.h"
#include "utils/stats.h"
#include "log/messages.h"

THREAD_LOCAL ProfileStats bindPerfStats;

//-------------------------------------------------------------------------
// binding
//-------------------------------------------------------------------------

Binding::Binding()
{
    when.nets = nullptr;
    when.protos = PROTO_BIT__ALL;

    when.vlans.set();
    when.ports.set();

    when.id = 0;
    when.role = BR_EITHER;
    use.action = BA_INSPECT;
}

Binding::~Binding()
{
    if ( when.nets )
        sfvar_free(when.nets);
}

bool Binding::check_policy(const Flow* flow) const
{
    if ( !when.id )
        return true;

    if ( when.id == flow->policy_id )
        return true;

    return false;
}

bool Binding::check_addr(const Flow* flow) const
{
    if ( !when.nets )
        return true;

    if ( sfvar_ip_in(when.nets, &flow->client_ip) )
        return true;

    if ( sfvar_ip_in(when.nets, &flow->server_ip) )
        return true;

    return false;
}

bool Binding::check_proto(const Flow* flow) const
{
    unsigned mask = when.protos;
    unsigned bit = 0;

    switch ( flow->protocol )
    {
    case IPPROTO_IP:   bit = PROTO_BIT__IP;   break;
    case IPPROTO_ICMP: bit = PROTO_BIT__ICMP; break;
    case IPPROTO_TCP:  bit = PROTO_BIT__TCP;  break;
    case IPPROTO_UDP:  bit = PROTO_BIT__UDP;  break;
    }
    return ( mask & bit ) != 0;
}

bool Binding::check_vlan(const Flow* flow) const
{
    unsigned v = flow->key->vlan_tag;
    return when.vlans.test(v);
}

bool Binding::check_port(const Flow* flow) const
{
    return when.ports.test(flow->server_port);
}

bool Binding::check_service(const Flow* flow) const
{
    if ( !flow->service )
        return when.svc.empty();

    if ( when.svc == flow->service )
        return true;

    return false;
}

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

// FIXIT-H bind this is a temporary hack. note that both ends must be set
// independently and that we must ref count inspectors.
static void set_session(Flow* flow, const char* key)
{
    Inspector* pin = InspectorManager::get_inspector(key);

    if ( pin )
    {
        flow->set_client(pin);
        flow->set_server(pin);
        flow->clouseau = nullptr;
    }
}

static void set_session(Flow* flow)
{
    flow->ssn_client = nullptr;
    flow->ssn_server = nullptr;
    flow->clouseau = nullptr;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Binder : public Inspector
{
public:
    Binder(vector<Binding*>);
    ~Binder();

    void show(SnortConfig*)
    { LogMessage("Binder\n"); };

    void eval(Packet*);
    int exec(int, void*);

    void add(Binding* b)
    { bindings.push_back(b); };

private:
    void init_flow(Flow*);
    Binding* get_binding(const Flow*);
    BindAction apply(Flow*, Binding*);
    Inspector* find_inspector(const Flow*);

private:
    vector<Binding*> bindings;
};

Binder::Binder(vector<Binding*> v)
{
    bindings = v;
}

Binder::~Binder()
{
    for ( auto* p : bindings )
        delete p;
}

void Binder::eval(Packet* p)
{
    Flow* flow = p->flow;

    Binding* pb = get_binding(flow);
    flow->flow_state = apply(flow, pb);

    ++bstats.verdicts[flow->flow_state - 1];
    ++bstats.packets;
}

// FIXIT-H implement inspector lookup from policy / bindings
Inspector* Binder::find_inspector(const Flow* flow)
{
    Binding* pb = get_binding(flow);

    if ( !pb )
        return nullptr;

    Inspector* ins = InspectorManager::get_inspector(pb->use.type.c_str());
    return ins;
}

int Binder::exec(int, void* pv)
{
    Flow* flow = (Flow*)pv;
    Inspector* ins = find_inspector(flow);

    if ( ins )
        flow->set_gadget(ins);

    if ( flow->protocol != IPPROTO_TCP )
        return 0;

    if ( ins )
    {
        stream.set_splitter(flow, true, ins->get_splitter(true));
        stream.set_splitter(flow, false, ins->get_splitter(false));
    }
    else
    {
        stream.set_splitter(flow, true, new AtomSplitter(true));
        stream.set_splitter(flow, false, new AtomSplitter(false));
    }

    return 0;
}

// FIXIT-L this is a simple linear search until functionality is nailed
// down.  performance could be improved by breaking bindings up into
// multiple lists by proto and service or by using a more sophisticated
// approach like routing tables, avl or scapegoat tree, etc.
Binding* Binder::get_binding(const Flow* flow)
{
    Binding* pb;
    unsigned i, sz = bindings.size();

    for ( i = 0; i < sz; i++ )
    {
        pb = bindings[i];

        // FIXIT-H file must be implemented and should not be in runtime
        // list of bindings
        if ( pb->use.file.size() )
            continue;

        if ( !pb->check_policy(flow) )
            continue;

        if ( !pb->check_vlan(flow) )
            continue;

        // FIXIT-H need to check role and addr/ports relative to it
        if ( !pb->check_addr(flow) )
            continue;

        if ( !pb->check_proto(flow) )
            continue;

        if ( !pb->check_port(flow) )
            continue;

        if ( !pb->check_service(flow) )
            continue;

        return pb;
    }

    // absent a specific rule, we must choose a course of action
    // so we act as if binder wasn't configured at all
    return nullptr;
}
    
BindAction Binder::apply(Flow* flow, Binding* pb)
{
    if ( !pb )
        return BA_ALLOW;

    if ( pb->use.action != BA_INSPECT )
    {
        if ( pb->use.action == BA_BLOCK )
            stream.drop_traffic(flow, SSN_DIR_BOTH);
        return pb->use.action;
    }

    init_flow(flow);
    Inspector* ins;

    if ( !pb->use.type.size() || pb->use.type == "wizard" )
    {
        ins = InspectorManager::get_wizard();
        flow->set_clouseau(ins);
    }
    else
    {
        ins = InspectorManager::get_inspector(pb->use.type.c_str()); 
        flow->set_gadget(ins);
    }
    return BA_INSPECT;
}

void Binder::init_flow(Flow* flow)
{
    switch ( flow->protocol )
    {
    case IPPROTO_IP:
        set_session(flow, "stream_ip");
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

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new BinderModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* bind_ctor(Module* m)
{
    BinderModule* mod = (BinderModule*)m;
    vector<Binding*> pb = mod->get_data();
    return new Binder(pb);
}

static void bind_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi bind_api =
{
    {
        PT_INSPECTOR,
        BIND_NAME,
        BIND_HELP,
        INSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    IT_BINDER, 
    PROTO_BIT__ALL,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    bind_ctor,
    bind_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* nin_binder = &bind_api.base;

