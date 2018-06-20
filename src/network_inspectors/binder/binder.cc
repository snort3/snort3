//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/flow.h"
#include "flow/flow_key.h"
#include "framework/data_bus.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "target_based/sftarget_reader.h"
#include "target_based/snort_protocols.h"

#include "bind_module.h"
#include "binding.h"

using namespace snort;
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
    when.split_nets = false;
    when.src_nets = nullptr;
    when.dst_nets = nullptr;

    when.split_ports = false;
    when.src_ports.set();
    when.dst_ports.set();

    when.protos = PROTO_BIT__ANY_TYPE;
    when.vlans.set();
    when.ifaces.reset();

    when.src_zone = DAQ_PKTHDR_UNKNOWN;
    when.dst_zone = DAQ_PKTHDR_UNKNOWN;

    when.ips_id = 0;
    when.role = BindWhen::BR_EITHER;

    use.inspection_index = 0;
    use.ips_index = 0;
    use.network_index = 0;
    use.action = BindUse::BA_INSPECT;

    use.what = BindUse::BW_NONE;
    use.object = nullptr;
}

Binding::~Binding()
{
    if ( when.src_nets )
        sfvar_free(when.src_nets);

    if ( when.dst_nets )
        sfvar_free(when.dst_nets);
}

inline bool Binding::check_ips_policy(const Flow* flow) const
{
    if ( !when.ips_id )
        return true;

    if ( when.ips_id == flow->ips_policy_id )
        return true;

    return false;
}

inline bool Binding::check_addr(const Flow* flow) const
{
    if ( when.split_nets )
        return true;

    if ( !when.src_nets )
        return true;

    switch ( when.role )
    {
        case BindWhen::BR_SERVER:
            if ( sfvar_ip_in(when.src_nets, &flow->server_ip) )
                return true;
            break;

        case BindWhen::BR_CLIENT:
            if ( sfvar_ip_in(when.src_nets, &flow->client_ip) )
                return true;
            break;

        case BindWhen::BR_EITHER:
            if ( sfvar_ip_in(when.src_nets, &flow->client_ip) or
                   sfvar_ip_in(when.src_nets, &flow->server_ip) )
                return true;
            break;

        default:
            break;
    }
    return false;
}

inline bool Binding::check_proto(const Flow* flow) const
{
    if ( when.protos & BIT((unsigned)flow->pkt_type) )
        return true;

    return false;
}

inline bool Binding::check_iface(const Packet* p) const
{
    if ( !p or when.ifaces.none() )
        return true;

    auto in = p->pkth->ingress_index;
    auto out = p->pkth->egress_index;

    if ( in > 0 and when.ifaces.test(out) )
        return true;

    if ( out > 0 and when.ifaces.test(in) )
        return true;

    return false;
}

inline bool Binding::check_vlan(const Flow* flow) const
{
    unsigned v = flow->key->vlan_tag;
    return when.vlans.test(v);
}

inline bool Binding::check_port(const Flow* flow) const
{
    if ( when.split_ports )
        return true;

    switch ( when.role )
    {
        case BindWhen::BR_SERVER:
            return when.src_ports.test(flow->server_port);
        case BindWhen::BR_CLIENT:
            return when.src_ports.test(flow->client_port);
        case BindWhen::BR_EITHER:
            return (when.src_ports.test(flow->client_port) or
                when.src_ports.test(flow->server_port) );
        default:
            break;
    }
    return false;
}

inline bool Binding::check_service(const Flow* flow) const
{
    if ( !flow->service )
        return when.svc.empty();

    if ( when.svc == flow->service )
        return true;

    return false;
}

// we want to correlate src_zone to src_nets and src_ports, and dst_zone to dst_nets and
// dst_ports. it doesn't matter if the packet is actually moving in the opposite direction as
// binder is only evaluated once per flow and we need to capture the correct binding from
// either side of the conversation
template<typename When, typename Traffic, typename Compare>
static Binding::DirResult directional_match(const When& when_src, const When& when_dst,
    const Traffic& traffic_src, const Traffic& traffic_dst,
    const Binding::DirResult dr, const Compare& compare)
{
    bool src_in_src = false;
    bool src_in_dst = false;
    bool dst_in_src = false;
    bool dst_in_dst = false;
    bool forward_match = false;
    bool reverse_match = false;

    switch ( dr )
    {
        case Binding::DR_ANY_MATCH:
            src_in_src = compare(when_src, traffic_src);
            src_in_dst = compare(when_dst, traffic_src);
            dst_in_src = compare(when_src, traffic_dst);
            dst_in_dst = compare(when_dst, traffic_dst);

            forward_match = src_in_src and dst_in_dst;
            reverse_match = dst_in_src and src_in_dst;

            if ( forward_match and reverse_match )
                return dr;

            if ( forward_match )
                return Binding::DR_FORWARD;
            
            if ( reverse_match )
                return Binding::DR_REVERSE;

            return Binding::DR_NO_MATCH;

        case Binding::DR_FORWARD:
            src_in_src = compare(when_src, traffic_src);
            dst_in_dst = compare(when_dst, traffic_dst);
            return src_in_src and dst_in_dst ? dr : Binding::DR_NO_MATCH;

        case Binding::DR_REVERSE:
            src_in_dst = compare(when_dst, traffic_src);
            dst_in_src = compare(when_src, traffic_dst);
            return src_in_dst and dst_in_src ? dr : Binding::DR_NO_MATCH;

        default:
            break;
    }

    return Binding::DR_NO_MATCH;
}

inline Binding::DirResult Binding::check_split_addr(
    const Flow* flow, const Packet* p, const Binding::DirResult dr) const
{
    if ( !when.split_nets )
        return dr;

    if ( !when.src_nets && !when.dst_nets )
        return dr;
    
    const SfIp* src_ip;
    const SfIp* dst_ip;

    if ( p && p->ptrs.ip_api.is_ip() )
    {
        src_ip = p->ptrs.ip_api.get_src();
        dst_ip = p->ptrs.ip_api.get_dst();
    }
    else
    {
        src_ip = &flow->client_ip;
        dst_ip = &flow->server_ip;
    }

    return directional_match(when.src_nets, when.dst_nets, src_ip, dst_ip, dr,
        [](sfip_var_t* when_val, const SfIp* traffic_val)
        { return when_val ? sfvar_ip_in(when_val, traffic_val) : true; });
}

inline Binding::DirResult Binding::check_split_port(
    const Flow* flow, const Packet* p, const Binding::DirResult dr) const
{
    if ( !when.split_ports )
        return dr;
    
    uint16_t src_port;
    uint16_t dst_port;

    if ( !p )
    {
        src_port = flow->client_port; 
        dst_port = flow->server_port; 
    }
    else if ( p->is_tcp() or p->is_udp() )
    {
        src_port = p->ptrs.sp;
        dst_port = p->ptrs.dp;
    }
    else
        return dr;

    return directional_match(when.src_ports, when.dst_ports, src_port, dst_port, dr,
        [](const PortBitSet& when_val, uint16_t traffic_val)
        { return when_val.test(traffic_val); });
}

inline Binding::DirResult Binding::check_zone(
    const Packet* p, const Binding::DirResult dr) const
{
    if ( !p )
        return dr;

    return directional_match(when.src_zone, when.dst_zone,
        p->pkth->ingress_group, p->pkth->egress_group, dr,
        [](int32_t when_val, int32_t zone)
        { return when_val == DAQ_PKTHDR_UNKNOWN or when_val == zone; });
}

bool Binding::check_all(const Flow* flow, Packet* p) const
{
    Binding::DirResult dir = Binding::DR_ANY_MATCH;

    if ( !check_ips_policy(flow) )
        return false;

    if ( !check_iface(p) )
        return false;

    if ( !check_vlan(flow) )
        return false;

    // FIXIT-M need to check role and addr/ports relative to it
    if ( !check_addr(flow) )
        return false;

    dir = check_split_addr(flow, p, dir);
    if ( dir == Binding::DR_NO_MATCH )
        return false;

    if ( !check_proto(flow) )
        return false;

    if ( !check_port(flow) )
        return false;

    dir = check_split_port(flow, p, dir);
    if ( dir == Binding::DR_NO_MATCH )
        return false;

    if ( !check_service(flow) )
        return false;

    dir = check_zone(p, dir);
    if ( dir == Binding::DR_NO_MATCH )
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
    Stream::set_snort_protocol_id(flow, host, FROM_SERVER);
}

static Inspector* get_gadget(Flow* flow)
{
    if ( !flow->ssn_state.snort_protocol_id )
        return nullptr;

    const char* s = SnortConfig::get_conf()->proto_ref->get_name(flow->ssn_state.snort_protocol_id);

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

        if ( !flow->ssn_state.snort_protocol_id )
            flow->ssn_state.snort_protocol_id = gadget->get_service();
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
    ~Binder() override;

    void show(SnortConfig*) override
    { LogMessage("Binder\n"); }

    void remove_inspector_binding(SnortConfig*, const char*) override;

    bool configure(SnortConfig*) override;

    void eval(Packet*) override { }

    void add(Binding* b)
    { bindings.push_back(b); }

    void handle_flow_setup(Packet*);
    void handle_flow_service_change(Flow*);
    void handle_new_standby_flow(Flow*);

private:
    void apply(const Stuff&, Flow*);

    void set_binding(SnortConfig*, Binding*);
    void get_bindings(Flow*, Stuff&, Packet* = nullptr); // may be null when dealing with HA flows
    void apply(Flow*, Stuff&);
    Inspector* find_gadget(Flow*);

private:
    vector<Binding*> bindings;
};

class FlowStateSetupHandler : public DataHandler
{
public:
    FlowStateSetupHandler() = default;

    void handle(DataEvent& event, Flow* flow) override
    {
        Binder* binder = InspectorManager::get_binder();
        if (binder && flow)
            binder->handle_flow_setup(const_cast<Packet*>(event.get_packet()));
    }
};

// When a flow's service changes, re-evaluate service to inspector mapping.
class FlowServiceChangeHandler : public DataHandler
{
public:
    FlowServiceChangeHandler() = default;

    void handle(DataEvent&, Flow* flow) override
    {
        Binder* binder = InspectorManager::get_binder();
        if (binder && flow)
            binder->handle_flow_service_change(flow);
    }
};

class StreamHANewFlowHandler : public DataHandler
{
public:
    StreamHANewFlowHandler() = default;

    void handle(DataEvent&, Flow* flow) override
    {
        Binder* binder = InspectorManager::get_binder();
        if (binder && flow)
            binder->handle_new_standby_flow(flow);
    }
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
    unsigned sz = bindings.size();

    for ( unsigned i = 0; i < sz; i++ )
    {
        Binding* pb = bindings[i];

        // Update with actual policy indices instead of user provided names
        if ( pb->when.ips_id )
        {
            IpsPolicy* p = sc->policy_map->get_user_ips(pb->when.ips_id);
            if ( p )
                pb->when.ips_id = p->policy_id;
            else
                ParseError("can't bind. ips_policy_id %u does not exist", pb->when.ips_id);
        }

        if ( !pb->use.ips_index and !pb->use.inspection_index and !pb->use.network_index )
            set_binding(sc, pb);
    }

    DataBus::subscribe(FLOW_STATE_SETUP_EVENT, new FlowStateSetupHandler());
    DataBus::subscribe(FLOW_SERVICE_CHANGE_EVENT, new FlowServiceChangeHandler());
    DataBus::subscribe(STREAM_HA_NEW_FLOW_EVENT, new StreamHANewFlowHandler());

    return true;
}

void Binder::remove_inspector_binding(SnortConfig*, const char* name)
{
    vector<Binding*>::iterator it;
    for ( it = bindings.begin(); it != bindings.end(); ++it )
    {
        const char* key;
        Binding *pb = *it;
        if ( pb->use.svc.empty() )
            key = pb->use.name.c_str();
        else
            key = pb->use.svc.c_str();
        if ( !strcmp(key, name) )
        {
            bindings.erase(it);
            delete pb;
            return;
        }
    }
}

void Binder::handle_flow_setup(Packet* p)
{
    Profile profile(bindPerfStats);
    Stuff stuff;
    Flow* flow = p->flow;

    get_bindings(flow, stuff, p);
    apply(flow, stuff);

    ++bstats.verdicts[stuff.action];
    ++bstats.packets;
}

void Binder::handle_flow_service_change( Flow* flow )
{
    Profile profile(bindPerfStats);

    assert(flow);

    Inspector* ins = find_gadget(flow);

    if ( ins )
    {
        if (flow->gadget != nullptr )
            flow->clear_gadget();
        flow->set_gadget(ins);
        flow->ssn_state.snort_protocol_id = ins->get_service();
    }
    else if ( flow->service )
        flow->ssn_state.snort_protocol_id = SnortConfig::get_conf()->proto_ref->find(flow->service);

    if ( !flow->is_stream() )
        return;

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
}

void Binder::handle_new_standby_flow( Flow* flow )
{
    Profile profile(bindPerfStats);

    Stuff stuff;
    get_bindings(flow, stuff);
    apply(flow, stuff);

    ++bstats.verdicts[stuff.action];
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
void Binder::get_bindings(Flow* flow, Stuff& stuff, Packet* p)
{
    unsigned sz = bindings.size();

    // Evaluate policy ID bindings first
    // FIXIT-P The way these are being used, the policy bindings should be a separate list if not a
    //          separate table entirely
    // FIXIT-L This will select the first policy ID of each type that it finds and ignore the rest.
    //          It gets potentially hairy if people start specifying overlapping policy types in
    //          overlapping rules.
    bool inspection_set = false, ips_set = false, network_set = false;
    for ( unsigned i = 0; i < sz; i++ )
    {
        Binding* pb = bindings[i];

        // Skip any rules that don't contain an ID for a policy type we haven't set yet.
        if ( (!pb->use.inspection_index or inspection_set) and
             (!pb->use.ips_index or ips_set) and
             (!pb->use.network_index or network_set) )
            continue;

        if ( !pb->check_all(flow, p) )
            continue;

        if ( pb->use.inspection_index and !inspection_set )
        {
            set_inspection_policy(SnortConfig::get_conf(), pb->use.inspection_index - 1);
            flow->inspection_policy_id = pb->use.inspection_index - 1;
            inspection_set = true;
        }

        if ( pb->use.ips_index and !ips_set )
        {
            set_ips_policy(SnortConfig::get_conf(), pb->use.ips_index - 1);
            flow->ips_policy_id = pb->use.ips_index - 1;
            ips_set = true;
        }

        if ( pb->use.network_index and !network_set )
        {
            set_network_policy(SnortConfig::get_conf(), pb->use.network_index - 1);
            flow->network_policy_id = pb->use.network_index - 1;
            network_set = true;
        }
    }

    Binder* sub = InspectorManager::get_binder();

    // If policy selection produced a new binder to use, use that instead.
    if ( sub && sub != this )
    {
        sub->get_bindings(flow, stuff, p);
        return;
    }

    // If we got here, that means that a sub-policy with a binder was not invoked.
    // Continue using this binder for the rest of processing.
    for ( unsigned i = 0; i < sz; i++ )
    {
        Binding* pb = bindings[i];

        if ( pb->use.ips_index or pb->use.inspection_index or pb->use.network_index )
            continue;

        if ( !pb->check_all(flow, p) )
            continue;

        if ( stuff.update(pb) )
            return;
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
    IT_PASSIVE,
    PROTO_BIT__ANY_TYPE,
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

