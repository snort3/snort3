//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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

// var_dependency.cc author Yurii Chalov <ychalov@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "var_dependency.h"

#include <list>
#include <string>

#include "parser/parse_conf.h"
#include "parser/vars.h"

struct WeakVariable
{
    std::string var_name;
    std::string value;
    bool is_resolved;
    bool is_visited;

    WeakVariable(const char* _var_name, const char* _value)
        : var_name(_var_name), value(_value), is_resolved(false), is_visited(false) {}
};

typedef bool (*parse_callback)(const char*, const char*);

static std::list<WeakVariable*> weak_nets, weak_ports;

static bool resolving_nets = false;
static bool resolving_ports = false;

static std::list<std::string> extract_variable_names(const char* input)
{
    std::list<std::string> variable_names;

    for (size_t begin = 0; input[begin] != '\0'; begin++)
    {
        if (input[begin] != '$')
            continue;

        size_t end = 0;
        for (end = begin + 1; input[end] != '\0' and (isalnum(input[end]) or input[end] == '_'); end++)
            ;

        std::string variable(input + begin + 1, end - begin - 1);
        variable_names.push_back(variable);
        begin = end - 1;
    }

    return variable_names;
}

static std::list<WeakVariable*> find_over_table(WeakVariable* var, const std::list<WeakVariable*>& vars)
{
    std::list<WeakVariable*> res;
    std::list<std::string> names = extract_variable_names(var->value.c_str());

    for (const auto& name : names)
    {
        for (auto v : vars)
        {
            if (!v->is_visited and (v->var_name == name))
            {
                res.push_back(v);
                break;
            }
        }
    }

    return res;
}

static bool set_variable(WeakVariable* var, std::list<WeakVariable*>& vars, parse_callback parse_variable)
{
    std::list<WeakVariable*> found_vars;

    found_vars = find_over_table(var, vars);
    for (auto found_var : found_vars)
    {
        found_var->is_visited = true;
        set_variable(found_var, vars, parse_variable);
    }

    if (var->is_resolved)
        return true;

    var->is_resolved = true;

    return parse_variable(var->var_name.c_str(), var->value.c_str());
}

static void resolve(std::list<WeakVariable*>& vars, parse_callback parse_variable)
{
    for (auto var : vars)
    {
        if (!var->is_resolved and !set_variable(var, vars, parse_variable))
            return;
    }
}

static void clear_list(std::list<WeakVariable*>& vars)
{
    for (auto& item : vars)
        delete item;

    vars.clear();
}

void resolve_nets()
{
    resolving_nets = true;
    resolve(weak_nets, ParseIpVar);
    resolving_nets = false;
    clear_list(weak_nets);
}

void resolve_ports()
{
    resolving_ports = true;
    resolve(weak_ports, ParsePortVar);
    resolving_ports = false;
    clear_list(weak_ports);
}

bool is_resolving_nets() { return resolving_nets; }
bool is_resolving_ports() { return resolving_ports; }

static void push_to_list(std::list<WeakVariable*>& vars, const char* var_name, const char* val)
{
    vars.push_back(new WeakVariable(var_name, val));
}

void push_to_weak_nets(const char* var_name, const char* val)
{
    push_to_list(weak_nets, var_name, val);
}

void push_to_weak_ports(const char* var_name, const char* val)
{
    push_to_list(weak_ports, var_name, val);
}
