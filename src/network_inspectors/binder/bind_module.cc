//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// bind_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bind_module.h"

#include <iomanip>

#include "log/messages.h"
#include "main/shell.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "parser/parse_ip.h"
#include "protocols/packet.h"

using namespace snort;
using namespace std;

#define FILE_KEY ".file"
#define INSPECTION_KEY ".inspection"
#define IPS_KEY ".ips"

unsigned int BinderModule::module_id = 0;

THREAD_LOCAL BindStats bstats;

static const PegInfo bind_pegs[] =
{
    { CountType::SUM, "raw_packets", "raw packets evaluated" },
    { CountType::SUM, "new_flows", "new flows evaluated" },
    { CountType::SUM, "rebinds", "flows rebound" },
    { CountType::SUM, "service_changes", "flow service changes evaluated" },
    { CountType::SUM, "assistant_inspectors", "flow assistant inspector requests handled" },
    { CountType::SUM, "new_standby_flows", "new HA flows evaluated" },
    { CountType::SUM, "no_match", "binding evaluations that had no matches" },
    { CountType::SUM, "resets", "reset actions bound" },
    { CountType::SUM, "blocks", "block actions bound" },
    { CountType::SUM, "allows", "allow actions bound" },
    { CountType::SUM, "inspects", "inspect actions bound" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// binder module
//-------------------------------------------------------------------------

static const Parameter binder_when_params[] =
{
    // FIXIT-L when.policy_id should be an arbitrary string auto converted
    // into index for binder matching and lookups

    { "ips_policy_id", Parameter::PT_INT, "0:max32", nullptr,
      "unique ID for selection of this config by external logic" },

    { "vlans", Parameter::PT_BIT_LIST, "4095", nullptr,
      "list of VLAN IDs" },

    { "nets", Parameter::PT_ADDR_LIST, nullptr, nullptr,
      "list of networks" },

    { "src_nets", Parameter::PT_ADDR_LIST, nullptr, nullptr,
      "list of source networks" },

    { "dst_nets", Parameter::PT_ADDR_LIST, nullptr, nullptr,
      "list of destination networks" },

    { "proto", Parameter::PT_ENUM, "any | ip | icmp | tcp | udp | user | file", nullptr,
      "protocol" },

    { "ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "list of ports" },

    { "src_ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "list of source ports" },

    { "dst_ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "list of destination ports" },

    { "intfs", Parameter::PT_STRING, nullptr, nullptr,
      "list of interface IDs" },

    { "src_intfs", Parameter::PT_STRING, nullptr, nullptr,
      "list of source interface IDs" },

    { "dst_intfs", Parameter::PT_STRING, nullptr, nullptr,
      "list of destination interface IDs" },

    { "groups", Parameter::PT_STRING, nullptr, nullptr,
      "list of interface group IDs" },

    { "src_groups", Parameter::PT_STRING, nullptr, nullptr,
      "list of source interface group IDs" },

    { "dst_groups", Parameter::PT_STRING, nullptr, nullptr,
      "list of destination group IDs" },

    { "addr_spaces", Parameter::PT_STRING, nullptr, nullptr,
      "list of address space IDs" },

    { "tenants", Parameter::PT_STRING, nullptr, nullptr,
      "list of tenants" },

    { "role", Parameter::PT_ENUM, "client | server | any", "any",
      "use the given configuration on one or any end of a session" },

    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "name of service to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter binder_use_params[] =
{
    { "action", Parameter::PT_ENUM, "reset | block | allow | inspect", "inspect",
      "what to do with matching traffic" },

    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "use configuration in given file" },

    { "inspection_policy", Parameter::PT_STRING, nullptr, nullptr,
      "use inspection policy from given file" },

    { "ips_policy", Parameter::PT_STRING, nullptr, nullptr,
      "use ips policy from given file" },

    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "override automatic service identification" },

    { "type", Parameter::PT_STRING, nullptr, nullptr,
      "select module for binding" },

    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "symbol name (defaults to type)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "when", Parameter::PT_TABLE, binder_when_params, nullptr,
      "match criteria" },

    { "use", Parameter::PT_TABLE, binder_use_params, nullptr,
      "target configuration" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

template<typename T>
static bool parse_int_set(const snort::Value& v, std::unordered_set<T>& set)
{
    assert(v.get_type() == snort::Value::VT_STR);

    set.clear();

    std::string pl = v.get_string();

    std::stringstream ss(pl);
    ss >> std::setbase(0);

    uint64_t n;

    while ( ss >> n )
    {
        if ( n > static_cast<uint64_t>(std::numeric_limits<T>::max()) )
            return false;

        set.insert(n);
    }
    if ( !ss.eof() )
        return false;

    return true;
}

BinderModule::BinderModule() : Module(BIND_NAME, BIND_HELP, s_params, true) { }

BinderModule::~BinderModule()
{
    bindings.clear();
    binding.clear();
}

ProfileStats* BinderModule::get_profile() const
{ return &bindPerfStats; }

bool BinderModule::add_policy_file(const char* name, const char* type)
{
    if (!policy_type.empty())
    {
        ParseError("Only one type of policy may be specified per binding");
        return false;
    }

    policy_filename = name;
    policy_type = type;

    return true;
}

static void set_ip_var(sfip_var_t*& var, const char* val)
{
    if ( var )
        sfvar_free(var);
    var = sfip_var_from_string(val, "binder");
}

bool BinderModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, BIND_NAME) )
    {
        binding.clear();
        policy_filename.clear();
        policy_type.clear();
    }

    if (!module_id)
        module_id = FlowData::create_flow_data_id();

    return true;
}

bool BinderModule::set(const char* fqn, Value& v, SnortConfig*)
{
    // both
    if ( !strcmp(fqn, "binder.when.service") )
    {
        binding.when.svc = v.get_string();
        binding.when.add_criteria(BindWhen::Criteria::BWC_SVC);
    }
    else if ( !strcmp(fqn, "binder.use.service") )
        binding.use.svc = v.get_string();

    // when
    else if ( v.is("ips_policy_id") )
    {
        binding.when.ips_id_user = v.get_uint32();
        binding.when.add_criteria(BindWhen::Criteria::BWC_IPS_ID);
    }
    else if ( v.is("vlans") )
    {
        v.get_bits(binding.when.vlans);
        binding.when.add_criteria(BindWhen::Criteria::BWC_VLANS);
    }
    else if ( v.is("nets") )
    {
        set_ip_var(binding.when.src_nets, v.get_string());
        binding.when.add_criteria(BindWhen::Criteria::BWC_NETS);
    }
    else if ( v.is("src_nets") )
    {
        set_ip_var(binding.when.src_nets, v.get_string());
        binding.when.add_criteria(BindWhen::Criteria::BWC_SPLIT_NETS);
    }
    else if ( v.is("dst_nets") )
    {
        set_ip_var(binding.when.dst_nets, v.get_string());
        binding.when.add_criteria(BindWhen::Criteria::BWC_SPLIT_NETS);
    }
    else if ( v.is("proto") )
    {
        const unsigned mask[] =
        {
            PROTO_BIT__ANY_TYPE, PROTO_BIT__IP, PROTO_BIT__ICMP,
            PROTO_BIT__TCP, PROTO_BIT__UDP, PROTO_BIT__USER, PROTO_BIT__FILE, PROTO_BIT__PDU,
        };
        binding.when.protos = mask[v.get_uint8()];
        binding.when.add_criteria(BindWhen::Criteria::BWC_PROTO);
    }
    else if ( v.is("ports") )
    {
        v.get_bits(binding.when.src_ports);
        binding.when.add_criteria(BindWhen::Criteria::BWC_PORTS);
    }
    else if ( v.is("src_ports") )
    {
        v.get_bits(binding.when.src_ports);
        binding.when.add_criteria(BindWhen::Criteria::BWC_SPLIT_PORTS);
    }
    else if ( v.is("dst_ports") )
    {
        v.get_bits(binding.when.dst_ports);
        binding.when.add_criteria(BindWhen::Criteria::BWC_SPLIT_PORTS);
    }
    else if ( v.is("intfs") )
    {
        if (!parse_int_set<int32_t>(v, binding.when.src_intfs))
            return false;
        binding.when.add_criteria(BindWhen::Criteria::BWC_INTFS);
    }
    else if ( v.is("src_intfs") )
    {
        if (!parse_int_set<int32_t>(v, binding.when.src_intfs))
            return false;
        binding.when.add_criteria(BindWhen::Criteria::BWC_SPLIT_INTFS);
    }
    else if ( v.is("dst_intfs") )
    {
        if (!parse_int_set<int32_t>(v, binding.when.dst_intfs))
            return false;
        binding.when.add_criteria(BindWhen::Criteria::BWC_SPLIT_INTFS);
    }
    else if ( v.is("groups") )
    {
        if (!parse_int_set<int16_t>(v, binding.when.src_groups))
            return false;
        binding.when.add_criteria(BindWhen::Criteria::BWC_GROUPS);
    }
    else if ( v.is("src_groups") )
    {
        if (!parse_int_set<int16_t>(v, binding.when.src_groups))
            return false;
        binding.when.add_criteria(BindWhen::Criteria::BWC_SPLIT_GROUPS);
    }
    else if ( v.is("dst_groups") )
    {
        if (!parse_int_set<int16_t>(v, binding.when.dst_groups))
            return false;
        binding.when.add_criteria(BindWhen::Criteria::BWC_SPLIT_GROUPS);
    }
    else if ( v.is("addr_spaces") )
    {
        if (!parse_int_set<uint32_t>(v, binding.when.addr_spaces))
            return false;
        binding.when.add_criteria(BindWhen::Criteria::BWC_ADDR_SPACES);
    }
    else if ( v.is("tenants") )
    {
        if (!parse_int_set<uint32_t>(v, binding.when.tenants))
            return false;
        binding.when.add_criteria(BindWhen::Criteria::BWC_TENANTS);
    }
    else if ( v.is("role") )
        binding.when.role = (BindWhen::Role)v.get_uint8();

    // use
    else if ( v.is("action") )
        binding.use.action = (BindUse::Action)(v.get_uint8());

    else if ( v.is("file") )
    {
        if (!add_policy_file(v.get_string(), FILE_KEY))
            return false;
    }
    else if ( v.is("inspection_policy") )
    {
        if (!add_policy_file(v.get_string(), INSPECTION_KEY))
            return false;
    }
    else if ( v.is("ips_policy") )
    {
        if (!add_policy_file(v.get_string(), IPS_KEY))
            return false;
    }
    else if ( v.is("name") )
        binding.use.name = v.get_string();

    else if ( v.is("type") )
        binding.use.type = v.get_string();

    return true;
}

bool BinderModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if ( !strcmp(fqn, BIND_NAME) && idx )
    {
        // When validation
        if ( binding.when.has_criteria(BindWhen::Criteria::BWC_NETS | BindWhen::Criteria::BWC_SPLIT_NETS) )
        {
            ParseError("Can't specify 'nets' in combination with either of 'src_nets' or 'dst_nets'");
            return false;
        }

        if ( binding.when.has_criteria(BindWhen::Criteria::BWC_PORTS | BindWhen::Criteria::BWC_SPLIT_PORTS) )
        {
            ParseError("Can't specify 'ports' in combination with either of 'src_ports' or 'dst_ports'");
            return false;
        }

        if ( binding.when.has_criteria(BindWhen::Criteria::BWC_INTFS | BindWhen::Criteria::BWC_SPLIT_INTFS) )
        {
            ParseError("Can't specify 'intfs' in combination with either of 'src_intfs' or 'dst_intfs'");
            return false;
        }

        if ( binding.when.has_criteria(BindWhen::Criteria::BWC_GROUPS | BindWhen::Criteria::BWC_SPLIT_GROUPS) )
        {
            ParseError("Can't specify 'groups' in combination with either of 'src_groups' or 'dst_groups'");
            return false;
        }

        // Use validation
        if ( !policy_filename.empty() )
        {
            // Policy binding - Co-opts the binding structure, but doesn't want most of it.
            if ( !binding.use.svc.empty() || !binding.use.type.empty() ||
                !binding.use.name.empty() || binding.use.action != BindUse::BA_INSPECT )
            {
                ParseError("Policy bindings cannot specify any other use options");
                return false;
            }

            if ( policy_type == FILE_KEY )
            {
                Shell* sh = new Shell(policy_filename.c_str());
                auto policies = sc->policy_map->add_shell(sh, get_network_parse_policy());
                binding.use.inspection_index = policies->inspection->policy_id;
                binding.use.ips_index = policies->ips->policy_id;
            }
            else if ( policy_type == INSPECTION_KEY )
            {
                Shell* sh = new Shell(policy_filename.c_str());
                InspectionPolicy* inspection_policy = sc->policy_map->add_inspection_shell(sh);
                binding.use.inspection_index = inspection_policy->policy_id;
            }
            else if ( policy_type == IPS_KEY )
            {
                Shell* sh = new Shell(policy_filename.c_str());
                IpsPolicy* ips_policy = sc->policy_map->add_ips_shell(sh);
                binding.use.ips_index = ips_policy->policy_id;
            }

            // Store the policy type and filename for verbose output
            binding.use.type = policy_type;
            binding.use.name = policy_filename;

            commit_policy_binding();
        }
        else
        {
            // Normal type binding (if name is given, it will be resolved to an inspector instance
            //  during configure)
            if ( !binding.use.type.empty() )
            {
                // Ensure that we can resolve the type to an extant module and that it is bindable
                const char *mod_name = binding.use.type.c_str();
                const Module* m = ModuleManager::get_module(mod_name);
                if ( !m )
                {
                    ParseError("Can't bind to unknown type '%s'", mod_name);
                    return false;
                }
                else if ( !m->is_bindable() )
                {
                    ParseError("Type '%s' is not bindable", mod_name);
                    return false;
                }
                else if ( m->get_usage() == Module::GLOBAL )
                    binding.use.global_type = true;

                if ( binding.use.name.empty() )
                    binding.use.name = binding.use.type;
            }
            else if ( !binding.use.name.empty() )
            {
                ParseError("Missing binding type for name '%s'", binding.use.name.c_str());
                return false;
            }

            commit_binding();
        }
    }

    return true;
}

void BinderModule::add(const char* svc, const char* type)
{
    binding.clear();
    binding.when.svc = svc;
    binding.when.add_criteria(BindWhen::Criteria::BWC_SVC);
    binding.use.type = type;
    binding.use.name = type;
    commit_binding();
}

void BinderModule::add(unsigned proto, const char* type)
{
    binding.clear();
    binding.when.protos = proto;
    binding.when.add_criteria(BindWhen::Criteria::BWC_PROTO);
    binding.use.type = type;
    binding.use.name = type;
    commit_binding();
}

void BinderModule::commit_binding()
{
    bindings.emplace_back(binding);
    binding.when.src_nets = nullptr;
    binding.when.dst_nets = nullptr;
}

void BinderModule::commit_policy_binding()
{
    policy_bindings.emplace_back(binding);
    binding.when.src_nets = nullptr;
    binding.when.dst_nets = nullptr;
}

vector<Binding>& BinderModule::get_bindings()
{
    return bindings; // move semantics
}

vector<Binding>& BinderModule::get_policy_bindings()
{
    return policy_bindings; // move semantics
}

const PegInfo* BinderModule::get_pegs() const
{ return bind_pegs; }

PegCount* BinderModule::get_counts() const
{ return (PegCount*)&bstats; }

