//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// binding.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "binding.h"

#include "flow/flow.h"
#include "flow/flow_key.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "protocols/packet.h"

using namespace snort;

Binding::Binding()
{
    when.src_nets = nullptr;
    when.dst_nets = nullptr;
    clear();
}

void Binding::clear()
{
    when.ips_id = 0;
    when.ips_id_user = 0;
    when.protos = PROTO_BIT__ANY_TYPE;
    when.role = BindWhen::BR_EITHER;
    when.svc.clear();

    if (when.src_nets)
    {
        sfvar_free(when.src_nets);
        when.src_nets = nullptr;
    }
    if (when.dst_nets)
    {
        sfvar_free(when.dst_nets);
        when.dst_nets = nullptr;
    }

    when.vlans.reset();

    when.src_ports.set();
    when.dst_ports.set();

    when.src_intfs.clear();
    when.dst_intfs.clear();

    when.src_groups.clear();
    when.dst_groups.clear();

    when.addr_spaces.clear();

    when.criteria_flags = 0;

    use.svc.clear();
    use.type.clear();
    use.name.clear();

    use.action = BindUse::BA_INSPECT;
    use.inspection_index = 0;
    use.ips_index = 0;
    use.what = BindUse::BW_NONE;
    use.inspector = nullptr;
    use.global_type = false;
}

void Binding::configure(const SnortConfig* sc)
{
    // Update with actual policy indices instead of user-provided identifiers
    if (when.ips_id_user)
    {
        IpsPolicy* p = sc->policy_map->get_user_ips(when.ips_id_user);
        if (p)
            when.ips_id = p->policy_id;
        else
            ParseError("Can't bind for unrecognized ips_policy_id %u", when.ips_id_user);
    }

    if (use.ips_index || use.inspection_index)
        return;

    if (use.action != BindUse::BA_INSPECT)
        return;

    if (!use.name.empty())
    {
        const char* name = use.name.c_str();
        Inspector* ins = InspectorManager::get_inspector(name, use.global_type, sc);
        if (ins)
        {
            switch (ins->get_api()->type)
            {
                case IT_STREAM:
                    switch (when.role)
                    {
                        case BindWhen::BR_CLIENT: use.what = BindUse::BW_CLIENT; break;
                        case BindWhen::BR_SERVER: use.what = BindUse::BW_SERVER; break;
                        default: use.what = BindUse::BW_STREAM; break;
                    }
                    break;
                case IT_WIZARD: use.what = BindUse::BW_WIZARD; break;
                case IT_SERVICE: use.what = BindUse::BW_GADGET; break;
                case IT_PASSIVE: use.what = BindUse::BW_PASSIVE; break;
                default: break;
            }
        }
        if (use.what == BindUse::BW_NONE)
            ParseError("Couldn't bind '%s'", name);
        else
            use.inspector = ins;
    }
}

inline bool Binding::check_ips_policy(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_IPS_ID))
        return true;

    return when.ips_id == flow.ips_policy_id;
}

inline bool Binding::check_ips_policy() const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_IPS_ID))
        return true;

    return when.ips_id == get_ips_policy()->policy_id;
}

inline bool Binding::check_vlan(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_VLANS))
        return true;

    return when.vlans.test(flow.key->vlan_tag);
}

inline bool Binding::check_vlan(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_VLANS))
        return true;

    return when.vlans.test(p->get_flow_vlan_id());
}

inline bool Binding::check_addr(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_NETS))
        return true;

    switch (when.role)
    {
        case BindWhen::BR_SERVER:
            if (sfvar_ip_in(when.src_nets, &flow.server_ip))
                return true;
            break;

        case BindWhen::BR_CLIENT:
            if (sfvar_ip_in(when.src_nets, &flow.client_ip))
                return true;
            break;

        case BindWhen::BR_EITHER:
            if (sfvar_ip_in(when.src_nets, &flow.client_ip) ||
                sfvar_ip_in(when.src_nets, &flow.server_ip))
                return true;
            break;

        default:
            break;
    }
    return false;
}

inline bool Binding::check_addr(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_NETS))
        return true;

    switch (when.role)
    {
        case BindWhen::BR_SERVER:
            if (sfvar_ip_in(when.src_nets, p->ptrs.ip_api.get_dst()))
                return true;
            break;

        case BindWhen::BR_CLIENT:
            if (sfvar_ip_in(when.src_nets, p->ptrs.ip_api.get_src()))
                return true;
            break;

        case BindWhen::BR_EITHER:
            if (sfvar_ip_in(when.src_nets, p->ptrs.ip_api.get_src()) ||
                sfvar_ip_in(when.src_nets, p->ptrs.ip_api.get_dst()))
                return true;
            break;

        default:
            break;
    }
    return false;
}

inline bool Binding::check_split_addr(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_SPLIT_NETS))
        return true;

    if (when.src_nets && !sfvar_ip_in(when.src_nets, &flow.client_ip))
        return false;

    if (when.dst_nets && !sfvar_ip_in(when.dst_nets, &flow.server_ip))
        return false;

    return true;
}

inline bool Binding::check_split_addr(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_SPLIT_NETS))
        return true;

    if (when.src_nets && !sfvar_ip_in(when.src_nets, p->ptrs.ip_api.get_src()))
        return false;

    if (when.dst_nets && !sfvar_ip_in(when.dst_nets, p->ptrs.ip_api.get_dst()))
        return false;

    return true;
}

inline bool Binding::check_proto(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_PROTO))
        return true;

    unsigned proto_bit = 1 << ((unsigned)flow.pkt_type - 1);
    return (when.protos & proto_bit) != 0;
}

inline bool Binding::check_proto(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_PROTO))
        return true;

    unsigned proto_bit = 1 << ((unsigned)p->type() - 1);
    return (when.protos & proto_bit) != 0;
}

inline bool Binding::check_port(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_PORTS))
        return true;

    if (flow.pkt_type != PktType::TCP && flow.pkt_type != PktType::UDP)
        return false;

    switch (when.role)
    {
        case BindWhen::BR_SERVER:
            if (when.src_ports.test(flow.server_port))
                return true;
            break;

        case BindWhen::BR_CLIENT:
            if (when.src_ports.test(flow.client_port))
                return true;
            break;

        case BindWhen::BR_EITHER:
            if (when.src_ports.test(flow.client_port) ||
                when.src_ports.test(flow.server_port))
                return true;
            break;

        default:
            break;
    }
    return false;
}

inline bool Binding::check_port(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_PORTS))
        return true;

    if (p->type() != PktType::TCP && p->type() != PktType::UDP)
        return false;

    switch (when.role)
    {
        case BindWhen::BR_SERVER:
            if (when.src_ports.test(p->ptrs.dp))
                return true;
            break;

        case BindWhen::BR_CLIENT:
            if (when.src_ports.test(p->ptrs.sp))
                return true;
            break;

        case BindWhen::BR_EITHER:
            if (when.src_ports.test(p->ptrs.sp) ||
                when.src_ports.test(p->ptrs.dp))
                return true;
            break;

        default:
            break;
    }
    return false;
}

inline bool Binding::check_split_port(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_SPLIT_PORTS))
        return true;

    if (flow.pkt_type != PktType::TCP && flow.pkt_type != PktType::UDP)
        return false;

    if (!when.src_ports.test(flow.client_port))
        return false;

    if (!when.dst_ports.test(flow.server_port))
        return false;

    return true;
}

inline bool Binding::check_split_port(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_SPLIT_PORTS))
        return true;

    if (p->type() != PktType::TCP && p->type() != PktType::UDP)
        return false;

    if (!when.src_ports.test(p->ptrs.sp))
        return false;

    if (!when.dst_ports.test(p->ptrs.dp))
        return false;

    return true;
}

inline bool Binding::check_intf(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_INTFS))
        return true;

    switch (when.role)
    {
        case BindWhen::BR_SERVER:
            if (when.src_intfs.count(flow.server_intf))
                return true;
            break;

        case BindWhen::BR_CLIENT:
            if (when.src_intfs.count(flow.client_intf))
                return true;
            break;

        case BindWhen::BR_EITHER:
            if (when.src_intfs.count(flow.client_intf) ||
                when.src_intfs.count(flow.server_intf))
                return true;
            break;

        default:
            break;
    }

    return false;
}

inline bool Binding::check_intf(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_INTFS))
        return true;

    switch (when.role)
    {
        case BindWhen::BR_SERVER:
            if (when.src_intfs.count(p->pkth->egress_index))
                return true;
            break;

        case BindWhen::BR_CLIENT:
            if (when.src_intfs.count(p->pkth->ingress_index))
                return true;
            break;

        case BindWhen::BR_EITHER:
            if (when.src_intfs.count(p->pkth->ingress_index) ||
                when.src_intfs.count(p->pkth->egress_index))
                return true;
            break;

        default:
            break;
    }

    return false;
}

inline bool Binding::check_split_intf(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_SPLIT_INTFS))
        return true;

    if (!when.src_intfs.empty() && !when.src_intfs.count(flow.client_intf))
        return false;

    if (!when.dst_intfs.empty() && !when.dst_intfs.count(flow.server_intf))
        return false;

    return true;
}

inline bool Binding::check_split_intf(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_SPLIT_INTFS))
        return true;

    if (!when.src_intfs.empty() && !when.src_intfs.count(p->pkth->ingress_index))
        return false;

    if (!when.dst_intfs.empty() && !when.dst_intfs.count(p->pkth->egress_index))
        return false;

    return true;
}

inline bool Binding::check_group(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_GROUPS))
        return true;

    switch (when.role)
    {
        case BindWhen::BR_SERVER:
            if (when.src_groups.count(flow.server_group))
                return true;
            break;

        case BindWhen::BR_CLIENT:
            if (when.src_groups.count(flow.client_group))
                return true;
            break;

        case BindWhen::BR_EITHER:
            if (when.src_groups.count(flow.client_group) ||
                when.src_groups.count(flow.server_group))
                return true;
            break;

        default:
            break;
    }

    return false;
}

inline bool Binding::check_group(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_GROUPS))
        return true;

    switch (when.role)
    {
        case BindWhen::BR_SERVER:
            if (when.src_groups.count(p->pkth->egress_group))
                return true;
            break;

        case BindWhen::BR_CLIENT:
            if (when.src_groups.count(p->pkth->ingress_group))
                return true;
            break;

        case BindWhen::BR_EITHER:
            if (when.src_groups.count(p->pkth->ingress_group) ||
                when.src_groups.count(p->pkth->egress_group))
                return true;
            break;

        default:
            break;
    }

    return false;
}

inline bool Binding::check_split_group(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_SPLIT_GROUPS))
        return true;

    if (!when.src_groups.empty() && !when.src_groups.count(flow.client_group))
        return false;

    if (!when.dst_groups.empty() && !when.dst_groups.count(flow.server_group))
        return false;

    return true;
}

inline bool Binding::check_split_group(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_SPLIT_GROUPS))
        return true;

    if (!when.src_groups.empty() && !when.src_groups.count(p->pkth->ingress_group))
        return false;

    if (!when.dst_groups.empty() && !when.dst_groups.count(p->pkth->egress_group))
        return false;

    return true;
}

inline bool Binding::check_address_space(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_ADDR_SPACES))
        return true;

    return when.addr_spaces.count(flow.key->addressSpaceId) != 0;
}

inline bool Binding::check_address_space(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_ADDR_SPACES))
        return true;

    return when.addr_spaces.count(p->pkth->address_space_id) != 0;
}

inline bool Binding::check_tenant(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_TENANTS))
        return true;

    return when.tenants.count(flow.tenant) != 0;
}

inline bool Binding::check_tenant(const Packet* p) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_TENANTS))
        return true;

    return when.tenants.count(p->pkth->address_space_id) != 0;
}

inline bool Binding::check_service(const Flow& flow) const
{
    if (!when.has_criteria(BindWhen::Criteria::BWC_SVC))
        return true;

    if (!flow.has_service())
        return false;

    return when.svc == flow.service->c_str();
}

inline bool Binding::check_service(const char* service) const
{
    // Special case for explicit service lookups: Service criteria must be
    //  specified (and match) to succeed.
    if (!when.has_criteria(BindWhen::Criteria::BWC_SVC))
        return false;

    return when.svc == service;
}

inline bool Binding::check_service() const
{
    return when.has_criteria(BindWhen::Criteria::BWC_SVC) ? false : true;
}

bool Binding::check_all(const Flow& flow, const char* service) const
{
    // Do the service check first to optimize service change re-evaluations
    if (service)
    {
        if (!check_service(service))
            return false;
    }
    else if (!check_service(flow))
        return false;

    if (!check_ips_policy(flow))
        return false;

    if (!check_vlan(flow))
        return false;

    if (!check_addr(flow))
        return false;

    if (!check_split_addr(flow))
        return false;

    if (!check_proto(flow))
        return false;

    if (!check_port(flow))
        return false;

    if (!check_split_port(flow))
        return false;

    if (!check_intf(flow))
        return false;

    if (!check_split_intf(flow))
        return false;

    if (!check_group(flow))
        return false;

    if (!check_split_group(flow))
        return false;

    if (!check_address_space(flow))
        return false;

    if (!check_tenant(flow))
        return false;

    return true;
}

bool Binding::check_all(const Packet* p) const
{
    if (!check_service())
        return false;

    if (!check_ips_policy())
        return false;

    if (!check_vlan(p))
        return false;

    if (!check_addr(p))
        return false;

    if (!check_split_addr(p))
        return false;

    if (!check_proto(p))
        return false;

    if (!check_port(p))
        return false;

    if (!check_split_port(p))
        return false;

    if (!check_intf(p))
        return false;

    if (!check_split_intf(p))
        return false;

    if (!check_group(p))
        return false;

    if (!check_split_group(p))
        return false;

    if (!check_address_space(p))
        return false;

    if (!check_tenant(p))
        return false;

    return true;
}

