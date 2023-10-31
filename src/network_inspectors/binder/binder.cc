//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "packet_io/active.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/assistant_gadget_event.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "target_based/host_attributes.h"

#include "bind_module.h"
#include "binding.h"

using namespace snort;

THREAD_LOCAL ProfileStats bindPerfStats;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

static Inspector* get_gadget(const SnortProtocolId protocol_id)
{
    if (protocol_id == UNKNOWN_PROTOCOL_ID)
        return nullptr;

    return InspectorManager::get_service_inspector_by_id(protocol_id);
}

static std::string to_string(const sfip_var_t* list)
{
    std::string ipset;

    if (!list or !list->head)
        return "";

    for (auto node = list->head; node; node = node->next)
    {
        SfIpString ip_str;
        auto ip = node->ip;

        ip->get_addr()->ntop(ip_str);
        ipset += std::string(ip_str);

        if (((ip->get_family() == AF_INET6) and (ip->get_bits() != 128)) or
            ((ip->get_family() == AF_INET) and (ip->get_bits() != 32)))
        {
            auto bits = ip->get_bits();
            bits -= (ip->get_family() == AF_INET and bits) ? 96 : 0;
            ipset += "/" + std::to_string(bits);
        }

        ipset += ", ";
    }

    if (!ipset.empty())
        ipset.erase(ipset.end() - 2, ipset.end());

    return ipset;
}

template <unsigned N>
static std::string to_string(const std::bitset<N>& bitset)
{
    std::stringstream ss;

    if (bitset.none() or bitset.all())
        return "";

    for (unsigned i = 0; i < bitset.size(); ++i)
        if (bitset[i])
            ss << i << " ";

    auto str = ss.str();
    if (!str.empty())
        str.pop_back();

    return str;
}

template <typename T>
static std::string to_string(const std::unordered_set<T>& set)
{
    if (set.empty())
        return "";

    std::vector<T> elements;
    elements.insert(elements.end(), set.begin(), set.end());
    std::sort(elements.begin(), elements.end());

    std::stringstream ss;
    for (auto e : elements)
        ss << e << " ";

    auto str = ss.str();
    if (!str.empty())
        str.pop_back();

    return str;
}

static std::string to_string(const BindWhen::Role& role)
{
    switch(role)
    {
        case BindWhen::BR_CLIENT:
            return "client";
        case BindWhen::BR_SERVER:
            return "server";
        default:
            return "";
    }
}

static std::string proto_to_string(unsigned proto)
{
    switch(proto)
    {
        case PROTO_BIT__IP:
            return "ip";
        case PROTO_BIT__ICMP:
            return "icmp";
        case PROTO_BIT__TCP:
            return "tcp";
        case PROTO_BIT__UDP:
            return "udp";
        case PROTO_BIT__USER:
            return "user";
        case PROTO_BIT__FILE:
            return "file";
        default:
            return "";
    }
}

static std::string to_string(const BindUse::Action& action)
{
    switch(action)
    {
        case BindUse::BA_RESET:
            return "reset";
        case BindUse::BA_BLOCK:
            return "block";
        case BindUse::BA_ALLOW:
            return "allow";
        default:
            return "";
    }
}

static std::string to_string(const BindWhen& bw)
{
    std::string when;

    when += "{";

    auto role = to_string(bw.role);
    if (!role.empty())
        when += " role = " + role + ",";

    if (bw.has_criteria(BindWhen::Criteria::BWC_IPS_ID))
        when += " ips_policy_id = " + std::to_string(bw.ips_id_user) + ",";

    if (bw.has_criteria(BindWhen::Criteria::BWC_VLANS))
    {
        auto vlans = to_string<4096>(bw.vlans);
        when += " vlans = " + vlans + ",";
    }

    if (bw.has_criteria(BindWhen::Criteria::BWC_SVC))
        when += " service = " + bw.svc + ",";

    if (bw.has_criteria(BindWhen::Criteria::BWC_SPLIT_NETS))
    {
        auto src_nets = to_string(bw.src_nets);
        auto dst_nets = to_string(bw.dst_nets);
        if (!src_nets.empty())
            when += " src_nets = " + src_nets + ",";
        if (!dst_nets.empty())
            when += " dst_nets = " + dst_nets + ",";
    }
    else if (bw.has_criteria(BindWhen::Criteria::BWC_NETS))
    {
        auto nets = to_string(bw.src_nets);
        when += " nets = " + nets + ",";
    }

    if (bw.has_criteria(BindWhen::Criteria::BWC_PROTO))
    {
        auto proto = proto_to_string(bw.protos);
        when += " proto = " + proto + ",";
    }

    if (bw.has_criteria(BindWhen::Criteria::BWC_SPLIT_PORTS))
    {
        auto src_ports = to_string<65536>(bw.src_ports);
        auto dst_ports = to_string<65536>(bw.dst_ports);
        if (!src_ports.empty())
            when += " src_ports = " + src_ports + ",";
        if (!dst_ports.empty())
            when += " dst_ports = " + dst_ports + ",";
    }
    else if (bw.has_criteria(BindWhen::Criteria::BWC_PORTS))
    {
        auto ports = to_string<65536>(bw.src_ports);
        when += " ports = " + ports + ",";
    }

    if (bw.has_criteria(BindWhen::Criteria::BWC_SPLIT_GROUPS))
    {
        auto src_groups = to_string<int16_t>(bw.src_groups);
        auto dst_groups = to_string<int16_t>(bw.dst_groups);
        if (!src_groups.empty())
            when += " src_groups = " + src_groups + ",";
        if (!dst_groups.empty())
            when += " dst_groups = " + dst_groups + ",";
    }
    else if (bw.has_criteria(BindWhen::Criteria::BWC_GROUPS))
    {
        auto groups = to_string<int16_t>(bw.src_groups);
        when += " groups = " + groups + ",";
    }

    if (bw.has_criteria(BindWhen::Criteria::BWC_SPLIT_INTFS))
    {
        auto src_intfs = to_string<int32_t>(bw.src_intfs);
        auto dst_intfs = to_string<int32_t>(bw.dst_intfs);
        if (!src_intfs.empty())
            when += " src_intfs = " + src_intfs + ",";
        if (!dst_intfs.empty())
            when += " dst_intfs = " + dst_intfs + ",";
    }
    else if (bw.has_criteria(BindWhen::Criteria::BWC_INTFS))
    {
        auto intfs = to_string<int32_t>(bw.src_intfs);
        when += " intfs = " + intfs + ",";
    }

    if (bw.has_criteria(BindWhen::Criteria::BWC_ADDR_SPACES))
    {
        auto addr_spaces = to_string<uint32_t>(bw.addr_spaces);
        when += " addr_spaces = " + addr_spaces + ",";
    }

    if (bw.has_criteria(BindWhen::Criteria::BWC_TENANTS))
    {
        auto tenants = to_string<uint32_t>(bw.tenants);
        when += " tenants = " + tenants + ",";
    }

    if (when.length() > 1)
        when.pop_back();

    when += " }";

    return when;
}

static std::string to_string(const BindUse& bu)
{
    std::string use;

    use += "{";

    auto action = to_string(bu.action);
    if (!action.empty())
        use += " action = " + action + ",";

    if (!bu.svc.empty())
        use += " service = " + bu.svc + ",";

    if (!bu.type.empty())
        use += " type = " + ((bu.type.at(0) == '.') ? bu.type.substr(1) : bu.type) + ",";

    if (!bu.name.empty() and (bu.type != bu.name))
        use += " name = " + bu.name + ",";

    if (use.length() > 1)
        use.pop_back();

    use += " }";

    return use;
}

//-------------------------------------------------------------------------
// stuff stuff
//-------------------------------------------------------------------------

struct Stuff
{
    BindUse::Action action = BindUse::BA_INSPECT;

    Inspector* client = nullptr;
    Inspector* server = nullptr;
    Inspector* wizard = nullptr;
    Inspector* gadget = nullptr;
    Inspector* data = nullptr;

    bool update(const Binding&);

    void apply_action(Packet*);
    void apply_action(Flow&);
    void apply_session(Flow&);
    void apply_service(Flow&);
    void apply_assistant(Flow&, const char*);
};

bool Stuff::update(const Binding& pb)
{
    if (pb.use.action != BindUse::BA_INSPECT)
    {
        action = pb.use.action;
        return true;
    }

    switch (pb.use.what)
    {
        case BindUse::BW_NONE:
            break;
        case BindUse::BW_PASSIVE:
            if (!data)
                data = pb.use.inspector;
            break;
        case BindUse::BW_CLIENT:
            if (!client)
                client = pb.use.inspector;
            break;
        case BindUse::BW_SERVER:
            if (!server)
                server = pb.use.inspector;
            break;
        case BindUse::BW_STREAM:
            if (!client)
                client = pb.use.inspector;
            if (!server)
                server = pb.use.inspector;
            break;
        case BindUse::BW_WIZARD:
            wizard = pb.use.inspector;
            return true;
        case BindUse::BW_GADGET:
            gadget = pb.use.inspector;
            return true;
        default:
            break;
    }
    return false;
}

void Stuff::apply_action(Packet* p)
{
    switch (action)
    {
        case BindUse::BA_RESET:
            // disable all preproc analysis and detection for this packet
            DetectionEngine::disable_all(p);
            p->active->reset_session(p, true);
            break;
        case BindUse::BA_BLOCK:
            // disable all preproc analysis and detection for this packet
            DetectionEngine::disable_all(p);
            p->active->block_session(p, true);
            break;
        case BindUse::BA_ALLOW:
            p->active->trust_session(p, true);
            break;
        case BindUse::BA_INSPECT:
            break;
        default:
            break;
    }
}

void Stuff::apply_action(Flow& flow)
{
    switch (action)
    {
        case BindUse::BA_RESET:
            flow.set_state(Flow::FlowState::RESET);
            break;
        case BindUse::BA_BLOCK:
            flow.set_state(Flow::FlowState::BLOCK);
            break;
        case BindUse::BA_ALLOW:
            flow.set_state(Flow::FlowState::ALLOW);
            break;
        case BindUse::BA_INSPECT:
            flow.set_state(Flow::FlowState::INSPECT);
            break;
        default:
            break;
    }
}

void Stuff::apply_session(Flow& flow)
{
    flow.set_client(client);
    flow.set_server(server);
}

void Stuff::apply_service(Flow& flow)
{
    if (data)
        flow.set_data(data);

    if (!gadget)
        gadget = get_gadget(flow.ssn_state.snort_protocol_id);

    if (gadget)
    {
        if (gadget != flow.gadget)
        {
            flow.set_gadget(gadget);

            if (flow.ssn_state.snort_protocol_id == UNKNOWN_PROTOCOL_ID)
                flow.ssn_state.snort_protocol_id = gadget->get_service();

            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::SERVICE_INSPECTOR_CHANGE,
                DetectionEngine::get_current_packet());
        }
    }
    else if (wizard)
        flow.set_clouseau(wizard);

    else if (!flow.flags.svc_event_generated)
    {
        DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_NO_SERVICE, DetectionEngine::get_current_packet());
        flow.flags.svc_event_generated = true;
    }
}

void Stuff::apply_assistant(Flow& flow, const char* service)
{
    if (!gadget)
        gadget = InspectorManager::get_service_inspector_by_service(service);

    if (gadget)
        flow.set_assistant_gadget(gadget);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Binder : public Inspector
{
public:
    Binder(std::vector<Binding>&, std::vector<Binding>&);
    ~Binder() override;

    void remove_inspector_binding(SnortConfig*, const char*) override;

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;

    void eval(Packet*) override { }

    void handle_packet(const Packet*);
    void handle_flow_setup(Flow&, bool standby = false);
    void handle_flow_service_change(Flow&);
    void handle_assistant_gadget(const char* service, Flow&);
    void handle_flow_after_reload(Flow&);

private:
    void get_policy_bindings(Flow&, const char* service);
    void get_policy_bindings(Packet*);
    void get_bindings(Flow&, Stuff&, const char* service = nullptr);
    void get_bindings(Packet*, Stuff&);
    void apply(Flow&, Stuff&);
    void apply_assistant(Flow&, Stuff&, const char*);
    Inspector* find_gadget(Flow&, Inspector*& data);

private:
    std::vector<Binding> bindings;
    std::vector<Binding> policy_bindings;
    Inspector* default_ssn_inspectors[to_utype(PktType::MAX)]{};
};

class NonFlowPacketHandler : public DataHandler
{
public:
    NonFlowPacketHandler() : DataHandler(BIND_NAME)
    { }

    void handle(DataEvent& e, Flow*) override
    {
        Binder* binder = InspectorManager::get_binder();
        if (binder)
            binder->handle_packet(e.get_packet());
    }
};

class FlowStateSetupHandler : public DataHandler
{
public:
    FlowStateSetupHandler() : DataHandler(BIND_NAME)
    { order = 100; }

    void handle(DataEvent&, Flow* flow) override
    {
        Binder* binder = InspectorManager::get_binder();
        if (binder && flow && !flow->flags.ha_flow)
            binder->handle_flow_setup(*flow);
    }
};

// When a flow's service changes, re-evaluate service to inspector mapping.
class FlowServiceChangeHandler : public DataHandler
{
public:
    FlowServiceChangeHandler() : DataHandler(BIND_NAME) { }

    void handle(DataEvent&, Flow* flow) override
    {
        Binder* binder = InspectorManager::get_binder();
        if (binder && flow)
            binder->handle_flow_service_change(*flow);
    }
};

class StreamHANewFlowHandler : public DataHandler
{
public:
    StreamHANewFlowHandler() : DataHandler(BIND_NAME)
    { order = 100; }

    void handle(DataEvent&, Flow* flow) override
    {
        Binder* binder = InspectorManager::get_binder();
        if (binder && flow)
            binder->handle_flow_setup(*flow, true);
    }
};

class AssistantGadgetHandler : public DataHandler
{
public:
    AssistantGadgetHandler() : DataHandler(BIND_NAME) { }

    void handle(DataEvent& event, Flow* flow) override
    {
        Binder* binder = InspectorManager::get_binder();
        AssistantGadgetEvent* assistant_event = (AssistantGadgetEvent*)&event;

        if (binder && flow)
            binder->handle_assistant_gadget(assistant_event->get_service(), *flow);
    }
};

class RebindFlow : public DataHandler
{
public:
    RebindFlow() : DataHandler(BIND_NAME) { }

    void handle(DataEvent&, Flow* flow) override
    {
        if (flow && Flow::FlowState::INSPECT == flow->flow_state)
        {
            Binder* binder = InspectorManager::get_binder();
            if (binder)
                binder->handle_flow_after_reload(*flow);
        }
    }
};

Binder::Binder(std::vector<Binding>& bv, std::vector<Binding>& pbv)
    : bindings(std::move(bv)),  policy_bindings(std::move(pbv))
{ }

Binder::~Binder()
{
    for (Binding& b : bindings)
        b.clear();

    for (Binding& b : policy_bindings)
        b.clear();
}

bool Binder::configure(SnortConfig* sc)
{
    for (Binding& b : bindings)
        b.configure(sc);

    for (Binding& b : policy_bindings)
        b.configure(sc);

    // Grab default session inspectors if they exist for this policy
    for (int proto = to_utype(PktType::NONE); proto < to_utype(PktType::MAX); proto++)
    {
        const char* name;
        switch (static_cast<PktType>(proto))
        {
            case PktType::IP:   name = "stream_ip"; break;
            case PktType::TCP:  name = "stream_tcp"; break;
            case PktType::UDP:  name = "stream_udp"; break;
            case PktType::ICMP: name = "stream_icmp"; break;
            case PktType::USER:  name = "stream_user"; break;
            case PktType::FILE: name = "stream_file"; break;
            default:            name = nullptr; break;
        }
        if (name)
            default_ssn_inspectors[proto] = InspectorManager::get_inspector(name, false, sc);
    }

    DataBus::subscribe(intrinsic_pub_key, IntrinsicEventIds::PKT_WITHOUT_FLOW, new NonFlowPacketHandler());
    DataBus::subscribe(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_SETUP, new FlowStateSetupHandler());
    DataBus::subscribe(intrinsic_pub_key, IntrinsicEventIds::FLOW_SERVICE_CHANGE, new FlowServiceChangeHandler());
    DataBus::subscribe(intrinsic_pub_key, IntrinsicEventIds::FLOW_ASSISTANT_GADGET, new AssistantGadgetHandler());
    DataBus::subscribe(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_RELOADED, new RebindFlow());

    DataBus::subscribe(stream_pub_key, StreamEventIds::HA_NEW_FLOW, new StreamHANewFlowHandler());

    return true;
}

void Binder::show(const SnortConfig*) const
{
    bool log_header = true;
    for (const Binding& b : bindings)
    {
        if (log_header)
        {
            ConfigLogger::log_option("bindings");
            log_header = false;
        }

        auto bind_when = "{ when = " + to_string(b.when) + ",";
        auto bind_use = "use = " + to_string(b.use) + " }";
        ConfigLogger::log_list("", bind_when.c_str(), "   ");
        ConfigLogger::log_list("", bind_use.c_str(), "   ", true);
    }

    log_header = true;
    for (const Binding& b : policy_bindings)
    {
        if (log_header)
        {
            ConfigLogger::log_option("policy_bindings");
            log_header = false;
        }

        auto bind_when = "{ when = " + to_string(b.when) + ",";
        auto bind_use = "use = " + to_string(b.use) + " }";
        ConfigLogger::log_list("", bind_when.c_str(), "   ");
        ConfigLogger::log_list("", bind_use.c_str(), "   ", true);
    }
}

void Binder::remove_inspector_binding(SnortConfig*, const char* name)
{
    for (auto it = bindings.begin(); it != bindings.end(); ++it)
    {
        const char* key;
        const Binding &b = *it;
        if (b.use.svc.empty())
            key = b.use.name.c_str();
        else
            key = b.use.svc.c_str();
        if (!strcmp(key, name))
        {
            bindings.erase(it);
            return;
        }
    }
}

void Binder::handle_packet(const Packet* pkt)
{
    // cppcheck-suppress unreadVariable
    Profile profile(bindPerfStats);

    Stuff stuff;
    Packet* p = const_cast<Packet*>(pkt);
    get_bindings(p, stuff);
    stuff.apply_action(p);

    bstats.raw_packets++;
    bstats.verdicts[stuff.action]++;
}

void Binder::handle_flow_setup(Flow& flow, bool standby)
{
    Profile profile(bindPerfStats);

    // FIXIT-M logic for applying information from the host attribute table likely doesn't belong
    // in binder, but it *does* need to occur before the binding lookup (for service information)
    HostAttriInfo host;
    HostAttriInfo* p_host = nullptr;
    if ( HostAttributesManager::get_host_attributes(flow.server_ip, flow.server_port, &host) )
        p_host = &host;

    if (p_host)
    {
        // Set the fragmentation (IP) or stream (TCP) policy from the host entry
        switch (flow.pkt_type)
        {
            case PktType::IP:
                flow.ssn_policy = p_host->frag_policy;
                break;
            case PktType::TCP:
                flow.ssn_policy = p_host->stream_policy;
                break;
            default:
                break;
        }

        Stream::set_snort_protocol_id_from_ha(&flow, p_host->snort_protocol_id);
        if (flow.ssn_state.snort_protocol_id != UNKNOWN_PROTOCOL_ID)
        {
            const SnortConfig* sc = SnortConfig::get_conf();
            flow.set_service(nullptr, sc->proto_ref->get_name(flow.ssn_state.snort_protocol_id));
        }
    }

    Stuff stuff;
    get_bindings(flow, stuff);
    apply(flow, stuff);

    if (standby)
        bstats.new_standby_flows++;
    else
        bstats.new_flows++;
    bstats.verdicts[stuff.action]++;
}

void Binder::handle_flow_service_change(Flow& flow)
{
    bstats.service_changes++;

    Profile profile(bindPerfStats);
    Stuff stuff;

    get_bindings(flow, stuff);
    if (stuff.action != BindUse::BA_INSPECT)
    {
        stuff.apply_action(flow);
        return;
    }

    Inspector* ins = nullptr;
    Inspector* data = nullptr;

    if (flow.service)
    {
        ins = find_gadget(flow, data);
        if (flow.gadget != ins)
        {
            if (flow.gadget)
                flow.clear_gadget();
            if (ins)
            {
                flow.set_gadget(ins);
                flow.ssn_state.snort_protocol_id = ins->get_service();
                flow.clear_session_flags(SSNFLAG_ABORT_CLIENT | SSNFLAG_ABORT_SERVER);
                if (data and data != flow.data)
                {
                    if (flow.data)
                        flow.clear_data();

                    flow.set_data(data);
                }
                DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::SERVICE_INSPECTOR_CHANGE,
                    DetectionEngine::get_current_packet());
            }
            else
                flow.ssn_state.snort_protocol_id = UNKNOWN_PROTOCOL_ID;
        }
    }
    else
    {
        // reset to wizard when service is not specified
        auto it = std::find_if(bindings.cbegin(), bindings.cend(),
            [](const Binding& b){ return b.use.what == BindUse::BW_WIZARD; });
        if (it != bindings.cend())
            ins = (*it).use.inspector;

        if (flow.gadget)
            flow.clear_gadget();
        if (flow.clouseau)
            flow.clear_clouseau();
        if (ins)
            flow.set_clouseau(ins);
        flow.ssn_state.snort_protocol_id = UNKNOWN_PROTOCOL_ID;
    }

    // If there is no inspector bound to this flow after the service change, see if there's at least
    // an associated protocol ID.
    if (!ins && flow.service)
        flow.ssn_state.snort_protocol_id = SnortConfig::get_conf()->proto_ref->find(flow.service);

    if (flow.is_stream())
    {
        if (ins)
        {
            Stream::set_splitter(&flow, true, ins->get_splitter(true));
            Stream::set_splitter(&flow, false, ins->get_splitter(false));
        }
        else
        {
            Stream::set_splitter(&flow, true, new AtomSplitter(true));
            Stream::set_splitter(&flow, false, new AtomSplitter(false));
        }
    }
}

void Binder::handle_assistant_gadget(const char* service, Flow& flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(bindPerfStats);

    Stuff stuff;
    get_bindings(flow, stuff, service);
    apply_assistant(flow, stuff, service);

    bstats.assistant_inspectors++;
}

void Binder::handle_flow_after_reload(Flow& flow)
{
    Stuff stuff;
    get_bindings(flow, stuff);
    stuff.apply_action(flow);

    bstats.rebinds++;
    bstats.verdicts[stuff.action]++;
}

void Binder::get_policy_bindings(Flow& flow, const char* service)
{
    unsigned inspection_index = 0;
    unsigned ips_index = 0;

    // FIXIT-L This will select the first policy ID of each type that it finds and ignore the rest.
    //          It gets potentially hairy if people start specifying overlapping policy types in
    //          overlapping rules.
    for (const Binding& b : policy_bindings)
    {
        // Skip any rules that don't contain an ID for a policy type we haven't set yet.
        if ((!b.use.inspection_index || inspection_index) && (!b.use.ips_index || ips_index))
            continue;

        if (!b.check_all(flow, service))
            continue;

        if (b.use.inspection_index && !inspection_index)
            inspection_index = b.use.inspection_index;

        if (b.use.ips_index && !ips_index)
            ips_index = b.use.ips_index;
    }

    if (inspection_index)
    {
        set_inspection_policy(inspection_index);
        if (!service)
            flow.inspection_policy_id = inspection_index;
    }

    if (ips_index)
    {
        const SnortConfig* sc = SnortConfig::get_conf();
        set_ips_policy(sc, ips_index);
        if (!service)
            flow.ips_policy_id = ips_index;
    }
}

void Binder::get_policy_bindings(Packet* p)
{
    unsigned inspection_index = 0;
    unsigned ips_index = 0;

    // FIXIT-L This will select the first policy ID of each type that it finds and ignore the rest.
    //          It gets potentially hairy if people start specifying overlapping policy types in
    //          overlapping rules.
    for (const Binding& b : policy_bindings)
    {
        // Skip any rules that don't contain an ID for a policy type we haven't set yet.
        if ((!b.use.inspection_index || inspection_index) && (!b.use.ips_index || ips_index))
            continue;

        if (!b.check_all(p))
            continue;

        if (b.use.inspection_index && !inspection_index)
            inspection_index = b.use.inspection_index;

        if (b.use.ips_index && !ips_index)
            ips_index = b.use.ips_index;
    }

    if (inspection_index)
    {
        set_inspection_policy(inspection_index);
        p->user_inspection_policy_id = get_inspection_policy()->user_policy_id;
    }

    if (ips_index)
    {
        const SnortConfig* sc = SnortConfig::get_conf();
        set_ips_policy(sc, ips_index);
        p->user_ips_policy_id = get_ips_policy()->user_policy_id;
    }
}

// FIXIT-P this is a simple linear search until functionality is nailed
// down.  performance should be the focus of the next iteration.
void Binder::get_bindings(Flow& flow, Stuff& stuff, const char* service)
{
    // Evaluate policy ID bindings first
    get_policy_bindings(flow, service);

    // If policy selection produced a new binder to use, use that instead.
    Binder* sub = InspectorManager::get_binder();
    if (sub && sub != this)
    {
        sub->get_bindings(flow, stuff, service);
        return;
    }

    // If we got here, that means that a sub-policy with a binder was not invoked.
    // Continue using this binder for the rest of processing.

    // Initialize the session inspector for both client and server to the default for this policy.
    stuff.client = stuff.server = default_ssn_inspectors[to_utype(flow.pkt_type)];

    for (const Binding& b : bindings)
    {
        if (!b.check_all(flow, service))
            continue;

        if (stuff.update(b))
            return;
    }

    bstats.no_match++;
}

void Binder::get_bindings(Packet* p, Stuff& stuff)
{
    // Evaluate policy ID bindings first
    get_policy_bindings(p);

    // If policy selection produced a new binder to use, use that instead.
    Binder* sub = InspectorManager::get_binder();
    if (sub && sub != this)
    {
        sub->get_bindings(p, stuff);
        return;
    }

    // If we got here, that means that a sub-policy with a binder was not invoked.
    // Continue using this binder for the rest of processing.

    // Initialize the session inspector for both client and server to the default for this policy.
    stuff.client = stuff.server = default_ssn_inspectors[to_utype(p->type())];

    for (const Binding& b : bindings)
    {
        if (!b.check_all(p))
            continue;

        if (stuff.update(b))
            return;
    }

    bstats.no_match++;
}

Inspector* Binder::find_gadget(Flow& flow, Inspector*& data)
{
    Stuff stuff;
    get_bindings(flow, stuff, flow.service);
    data = stuff.data;
    return stuff.gadget;
}

void Binder::apply(Flow& flow, Stuff& stuff)
{
    stuff.apply_action(flow);
    if (flow.flow_state != Flow::FlowState::INSPECT)
        return;

    stuff.apply_session(flow);
    stuff.apply_service(flow);
}

void Binder::apply_assistant(Flow& flow, Stuff& stuff, const char* service)
{
    stuff.apply_assistant(flow, service);
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
    std::vector<Binding>& bv = mod->get_bindings();
    std::vector<Binding>& pbv = mod->get_policy_bindings();
    return new Binder(bv, pbv);
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

