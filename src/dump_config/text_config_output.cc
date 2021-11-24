//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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
// text_config_output.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "text_config_output.h"

#include <iomanip>
#include <iostream>

#include "config_data.h"

using namespace snort;

static void dump_value(const BaseConfigNode* node, const std::string& config_name)
{
    const Value* value = node->get_value();
    if ( !value )
        return;

    if ( value->get_as_string().empty() )
        return;

    switch ( node->get_type() )
    {
    case Parameter::PT_BOOL:
    case Parameter::PT_IMPLIED:
    {
        std::string value_str = value->get_bool() ? "true" : "false";
        std::cout << config_name << "=" << value_str << std::endl;
        break;
    }
    case Parameter::PT_INT:
        std::cout << config_name << "=" << value->get_int64() << std::endl;
        break;
    case Parameter::PT_REAL:
        std::cout << config_name << "=" << value->get_real() << std::endl;
        break;
    default:
        std::cout << config_name << "=" << std::quoted(value->get_origin_string()) << std::endl;
        break;
    }
}

static void dump_tree(const BaseConfigNode* node, const std::string& config_name)
{
    if ( node->get_children().empty() and !node->get_parent_node() )
    {
        std::cout << config_name << std::endl;
        return;
    }

    Parameter::Type node_type = node->get_type();

    if ( node_type == Parameter::PT_TABLE )
    {
        for ( const auto child : node->get_children() )
            dump_tree(child, config_name + "." + child->get_name());
    }
    else if ( node_type == Parameter::PT_LIST )
    {
        char suffix[16];
        int list_index = 0;
        for ( const auto child : node->get_children() )
        {
            snprintf(suffix, 16, "[%i]", list_index);
            const std::string full_config_name = config_name + suffix;
            dump_tree(child, full_config_name);
            list_index++;
        }
    }
    else
        dump_value(node, config_name);
}

void TextConfigOutput::dump(const ConfigData& config_data)
{
    std::string output("consolidated config for ");
    output += config_data.file_name;
    std::cout << output << std::endl;

    for ( const auto config_tree: config_data.config_trees )
        dump_tree(config_tree, config_tree->get_name());
}

