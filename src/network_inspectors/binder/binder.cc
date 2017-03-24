//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// binder.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "binder.h"

#include "flow/flow.h"
#include "flow/flow_key.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "target_based/sftarget_reader.h"
#include "target_based/snort_protocols.h"

#include "bind_module.h"
#include "binding.h"

using namespace std;

THREAD_LOCAL ProfileStats bindPerfStats;

// FIXIT-P these lookups should be optimized when the dust settles
#define INS_IP   "stream_ip"
#define INS_ICMP "stream_icmp"
#define INS_TCP  "stream_tcp"
#define INS_UDP  "stream_udp"
#define INS_USER "stream_user"
#define INS_FILE "stream_file"

//-------------------------------------------------------------------------
// binding
//-------------------------------------------------------------------------

Binding::Binding()
{
    when.nets = nullptr;
    when.protos = (unsigned)PktType::ANY;

    when.vlans.set();
    when.ports.set();
    when.ifaces.set();

    when.id = 0;
    when.role = BindWhen::BR_EITHER;

    use.index = 0;
    use.action = BindUse::BA_INSPECT;

    use.what = BindUse::BW_NONE;
    use.object = nullptr;
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

    switch ( when.role )
    {
        case BindWhen::BR_SERVER:
            if ( sfvar_ip_in(when.nets, &flow->server_ip) )
                return true;
            break;
        case BindWhen::BR_CLIENT:
            if ( sfvar_ip_in(when.nets, &flow->client_ip) )
                return true;
            break;
        case BindWhen::BR_EITHER:
            if ( sfvar_ip_in(when.nets, &flow->client_ip) or
                    sfvar_ip_in(when.nets, &flow->server_ip) )
                return true;
            break;
        default:
            break;
    }


    return false;
}

bool Binding::check_proto(const Flow* flow) const
{
    if ( when.protos & (unsigned)flow->pkt_type )
        return true;

    return false;
}

bool Binding::check_iface(const Flow* flow) const
{
    int i = flow->iface_in < 0 ? 0 : flow->iface_in;

    if ( when.ifaces.test(i) )
        return true;

    i = flow->iface_out < 0 ? 0 : flow->iface_out;

    if ( when.ifaces.test(i) )
        return true;

    return false;
}

bool Binding::check_vlan(const Flow* flow) const
{
    unsigned v = flow->key->vlan_tag;
    return when.vlans.test(v);
}

bool Binding::check_port(const Flow* flow) const
{
    switch ( when.role )
    {
        case BindWhen::BR_SERVER:
            return when.ports.test(flow->server_port);
        case BindWhen::BR_CLIENT:
            return when.ports.test(flow->client_port);
        case BindWhen::BR_EITHER:
            return (when.ports.test(flow->client_port) or when.ports.test(flow->server_port) );
        default:
            break;
    }
    return false;
}

bool Binding::check_service(const Flow* flow) const
{
    if ( !flow->service )
        return when.svc.empty();

    if ( when.svc == flow->service )
        return true;

    return false;
}

bool Binding::check_all(const Flow* flow) const
{
    if ( !check_policy(flow) )
        return false;

    if ( !check_iface(flow) )
        return false;

    if ( !check_vlan(flow) )
        return false;

    // FIXIT-M need to check role and addr/ports relative to it
    if ( !check_addr(flow) )
        return false;

    if ( !check_proto(flow) )
        return false;

    if ( !check_port(flow) )
        return false;

    if ( !check_service(flow) )
        return false;

    return true;
}

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

static void set_session(Flow* flow, const char* key)
{
    Inspector* pin = InspectorManager::get_inspector(key);

    if ( pin )
    {
        // FIXIT-M need to set ssn client and server independently
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

static void set_service(Flow* flow, const HostAttributeEntry* host)
{
    Stream::set_application_protocol_id(flow, host, FROM_SERVER);
}

static Inspector* get_gadget(Flow* flow)
{
    if ( !flow->ssn_state.application_protocol )
        return nullptr;

    const char* s = snort_conf->proto_ref->get_name(flow->ssn_state.application_protocol);

    return InspectorManager::get_inspector(s);
}

//-------------------------------------------------------------------------
// stuff stuff
//-------------------------------------------------------------------------

struct Stuff
{
    BindUse::Action action;

    Inspector* client;
    Inspector* server;
    Inspector* wizard;
    Inspector* gadget;
    Inspector* data;

    Stuff()
    {
        action = BindUse::BA_INSPECT;
        client = server = nullptr;
        wizard = gadget = nullptr;
        data = nullptr;
    }

    bool update(Binding*);

    bool apply_action(Flow*);
    void apply_session(Flow*, const HostAttributeEntry*);
    void apply_service(Flow*, const HostAttributeEntry*);
};

bool Stuff::update(Binding* pb)
{
    if ( pb->use.action != BindUse::BA_INSPECT )
    {
        action = pb->use.action;
        return true;
    }
    switch ( pb->use.what )
    {
    case BindUse::BW_NONE:
        break;
    case BindUse::BW_PASSIVE:
        data = (Inspector*)pb->use.object;
        break;
    case BindUse::BW_CLIENT:
        client = (Inspector*)pb->use.object;
        break;
    case BindUse::BW_SERVER:
        server = (Inspector*)pb->use.object;
        break;
    case BindUse::BW_STREAM:
        client = server = (Inspector*)pb->use.object;
        break;
    case BindUse::BW_WIZARD:
        wizard = (Inspector*)pb->use.object;
        return true;
    case BindUse::BW_GADGET:
        gadget = (Inspector*)pb->use.object;
        return true;
    default:
        break;
    }
    return false;
}

bool Stuff::apply_action(Flow* flow)
{
    switch ( action )
    {
    case BindUse::BA_RESET:
        flow->set_state(Flow::FlowState::RESET);
        return false;

    case BindUse::BA_BLOCK:
        flow->set_state(Flow::FlowState::BLOCK);
        return false;

    case BindUse::BA_ALLOW:
        flow->set_state(Flow::FlowState::ALLOW);
        return false;

    default:
        break;
    }
    flow->set_state(Flow::FlowState::INSPECT);
    return true;
}

void Stuff::apply_session(Flow* flow, const HostAttributeEntry* host)
{
    if ( server )
    {
        flow->set_server(server);

        if ( client )
            flow->set_client(client);
        else
            flow->set_client(server);

        return;
    }

    switch ( flow->pkt_type )
    {
    case PktType::IP:
        set_session(flow, INS_IP);
        flow->ssn_policy = host ? host->hostInfo.fragPolicy : 0;
        break;

    case PktType::ICMP:
        set_session(flow, INS_ICMP);
        break;

    case PktType::TCP:
        set_session(flow, INS_TCP);
        flow->ssn_policy = host ? host->hostInfo.streamPolicy : 0;
        break;

    case PktType::UDP:
        set_session(flow, INS_UDP);
        break;

    case PktType::PDU:
        set_session(flow, INS_USER);
        break;

    case PktType::FILE:
        set_session(flow, INS_FILE);
        break;

    default:
        set_session(flow);
    }
}

void Stuff::apply_service(Flow* flow, const HostAttributeEntry* host)
{
    if ( data )
        flow->set_data(data);

    if ( host )
        set_service(flow, host);

    if ( !gadget )
        gadget = get_gadget(flow);

    if ( gadget )
    {
        flow->set_gadget(gadget);

        if ( !flow->ssn_state.application_protocol )
            flow->ssn_state.application_protocol = gadget->get_service();
    }

    else if ( wizard )
        flow->set_clouseau(wizard);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Binder : public Inspector
{
public:
    Binder(vector<Binding*>&);
    ~Binder();

    void show(SnortConfig*) override
    { LogMessage("Binder\n"); }

    bool configure(SnortConfig*) override;

    void eval(Packet*) override;
    int exec(int, void*) override;

    void add(Binding* b)
    { bindings.push_back(b); }

private:
    void apply(const Stuff&, Flow*);

    void set_binding(SnortConfig*, Binding*);
    void get_bindings(Flow*, Stuff&);
    void apply(Flow*, Stuff&);
    Inspector* find_gadget(Flow*);
    int exec_handle_gadget(void*);
    int exec_eval_standby_flow(void*);

private:
    vector<Binding*> bindings;
};

Binder::Binder(vector<Binding*>& v)
{
    bindings = std::move(v);
}

Binder::~Binder()
{
    for ( auto* p : bindings )
        delete p;
}

bool Binder::configure(SnortConfig* sc)
{
    Binding* pb;
    unsigned i, sz = bindings.size();

    for ( i = 0; i < sz; i++ )
    {
        pb = bindings[i];

        if ( !pb->use.index )
            set_binding(sc, pb);
    }
    return true;
}

// FIXIT-M need to consider binding of ips rules / policy
// possibly split bindings into these categories
void Binder::eval(Packet* p)
{
    Flow* flow = p->flow;
    flow->iface_in = p->pkth->ingress_index;
    flow->iface_out = p->pkth->egress_index;

    Stuff stuff;
    get_bindings(flow, stuff);
    apply(flow, stuff);

    ++bstats.verdicts[stuff.action];
    ++bstats.packets;
}

int Binder::exec_handle_gadget( void* pv )
{
    Flow* flow = (Flow*)pv;
    Inspector* ins = find_gadget(flow);

    if ( ins )
    {
        if (flow->gadget != nullptr )
            flow->clear_gadget();
        flow->set_gadget(ins);
        flow->ssn_state.application_protocol = ins->get_service();
    }
    else if ( flow->service )
        flow->ssn_state.application_protocol = snort_conf->proto_ref->find(flow->service);

    if ( !flow->is_stream() )
        return 0;

    if ( ins )
    {
        Stream::set_splitter(flow, true, ins->get_splitter(true));
        Stream::set_splitter(flow, false, ins->get_splitter(false));
    }
    else
    {
        Stream::set_splitter(flow, true, new AtomSplitter(true));
        Stream::set_splitter(flow, false, new AtomSplitter(false));
    }

    return 0;
}

// similar to eval(), but working on a Flow in HA Standby mode
int Binder::exec_eval_standby_flow( void* pv )
{
    Flow* flow = (Flow*)pv;

    Stuff stuff;
    get_bindings(flow, stuff);
    apply(flow, stuff);

    ++bstats.verdicts[stuff.action];
    return 0;
}

int Binder::exec(int operation, void* pv)
{
    switch( operation )
    {
        case BinderSpace::ExecOperation::HANDLE_GADGET:
            return exec_handle_gadget( pv );
        case BinderSpace::ExecOperation::EVAL_STANDBY_FLOW:
            return exec_eval_standby_flow( pv );
        default:
            return (-1);
    }
}

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------

void Binder::set_binding(SnortConfig*, Binding* pb)
{
    if ( pb->use.action != BindUse::BA_INSPECT )
        return;

    const char* key;
    if ( pb->use.svc.empty() )
        key = pb->use.name.c_str();
    else
        key = pb->use.svc.c_str();

    if ( (pb->use.object = InspectorManager::get_inspector(key)) )
    {
        switch ( InspectorManager::get_type(key) )
        {
        case IT_STREAM: pb->use.what = BindUse::BW_STREAM; break;
        case IT_WIZARD: pb->use.what = BindUse::BW_WIZARD; break;
        case IT_SERVICE: pb->use.what = BindUse::BW_GADGET; break;
        case IT_PASSIVE: pb->use.what = BindUse::BW_PASSIVE; break;
        default: break;
        }
    }
    if ( !pb->use.object )
        pb->use.what = BindUse::BW_NONE;

    if ( pb->use.what == BindUse::BW_NONE )
        ParseError("can't bind %s", key);
}

// FIXIT-P this is a simple linear search until functionality is nailed
// down.  performance should be the focus of the next iteration.
void Binder::get_bindings(Flow* flow, Stuff& stuff)
{
    Binding* pb;
    unsigned i, sz = bindings.size();

    for ( i = 0; i < sz; i++ )
    {
        pb = bindings[i];

        if ( !pb->check_all(flow) )
            continue;

        if ( !pb->use.index )
        {
            if ( stuff.update(pb) )
                return;
            else
                continue;
        }

        set_policies(snort_conf, pb->use.index - 1);
        flow->policy_id = pb->use.index - 1;

        Binder* sub = (Binder*)InspectorManager::get_binder();

        if ( sub )
        {
            sub->get_bindings(flow, stuff);
            return;
        }
    }
}

Inspector* Binder::find_gadget(Flow* flow)
{
    Stuff stuff;
    get_bindings(flow, stuff);
    return stuff.gadget;
}

void Binder::apply(Flow* flow, Stuff& stuff)
{
    // setup action
    if ( !stuff.apply_action(flow) )
        return;

    const HostAttributeEntry* host = SFAT_LookupHostEntryByIP(&flow->server_ip);

    // setup session
    stuff.apply_session(flow, host);

    // setup service
    stuff.apply_service(flow, host);
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
    vector<Binding*>& pb = mod->get_data();
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
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        BIND_NAME,
        BIND_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_BINDER,
    (uint16_t)PktType::ANY,
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

