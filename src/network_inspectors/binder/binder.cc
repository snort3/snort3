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

#include <vector>
using namespace std;

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

static const char* mod_name = "binder";

THREAD_LOCAL ProfileStats bindPerfStats;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

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

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Binder : public Inspector {
public:
    Binder(vector<Binding*>);
    ~Binder();

    void show(SnortConfig*)
    { LogMessage("Binder\n"); };

    void eval(Packet*);
    int exec(int, void*);

    Inspector* find_inspector(const char*);

    void add(Binding* b)
    { bindings.push_back(b); };

private:
    int check_rules(Flow*, Packet*);
    void init_flow(Flow*);

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
    flow->flow_state = check_rules(flow, p);
    ++bstats.total_packets;
}

// FIXIT implement inspector lookup from policy / bindings
Inspector* Binder::find_inspector(const char* s)
{
    Binding* pb;
    unsigned i, sz = bindings.size();

    for ( i = 0; i < sz; i++ )
    {
        pb = bindings[i];

        if ( pb->when_svc == s )
            break;
    }
        
    if ( i == sz )
        return nullptr;

    Inspector* ins = InspectorManager::get_inspector(pb->type.c_str());
    return ins;
}

int Binder::exec(int, void* pv)
{
    Flow* flow = (Flow*)pv;
    Inspector* ins = find_inspector(flow->service);

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

// FIXIT bind services - this is a temporary hack that just looks at ports,
// need to examine all key fields for matching.  ultimately need a routing
// table, scapegoat tree, etc.
int Binder::check_rules(Flow* flow, Packet* p)
{
    Binding* pb;
    unsigned i, sz = bindings.size();

    Port port = (p->packet_flags & PKT_FROM_CLIENT) ? p->dp : p->sp;

    if (p->proto_bits & PROTO_BIT__VLAN)
        uint16_t vlan = vlan::vth_vlan(layer::get_vlan_layer(p));

    for ( i = 0; i < sz; i++ )
    {
        pb = bindings[i];

        if ( !check_proto(flow, pb->proto) )
            continue;

        if ( pb->ports.test(port) )
            break;
    }
        
    if ( i == sz )
        return BA_ALLOW;  // default action FIXIT make configurable

    if ( pb->action != BA_INSPECT )
        return pb->action;

    init_flow(flow);
    Inspector* ins;

    if ( !pb->type.size() || pb->type == "wizard" )
    {
        ins = InspectorManager::get_inspector("wizard");
        flow->set_clouseau(ins);
    }
    else
    {
        ins = InspectorManager::get_inspector(pb->type.c_str()); 
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
        mod_name,
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

