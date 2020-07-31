//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// config_tree.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "config_tree.h"

#include <cassert>

#include "log/messages.h"

using namespace snort;

void ConfigTextFormat::print(const BaseConfigNode* parent, const std::string& config_name)
{
    static char buf[16];
    int list_index = 0;
    for ( const auto node : parent->get_children() )
    {
        std::string full_config_name(config_name);
        std::string node_name = node->get_name();

        if ( !node_name.empty() )
        {
            full_config_name += ".";
            full_config_name += node_name;
        }
        else
        {
            sprintf(buf, "%i", list_index++);
            full_config_name += "[";
            full_config_name += buf;
            full_config_name += "]";
        }

        print(node, full_config_name);
    }

    std::string config_data = parent->data();
    if ( !config_data.empty() )
        LogConfig("%s=%s\n", config_name.c_str(), config_data.c_str());
}

BaseConfigNode::BaseConfigNode(BaseConfigNode* p) :
    parent(p)
{}

void BaseConfigNode::add_child_node(BaseConfigNode* node)
{
    assert(node);
    children.push_back(node);
}

void BaseConfigNode::clear_nodes(BaseConfigNode* node)
{
    for ( auto& config_node : node->children )
        clear_nodes(config_node);

    delete node;
}

TreeConfigNode::TreeConfigNode(BaseConfigNode* parent_node,
    const std::string& node_name, const Parameter::Type node_type) :
        BaseConfigNode(parent_node), name(node_name), type(node_type)
{}

BaseConfigNode* TreeConfigNode::get_node(const std::string& name)
{
    for ( auto node : children )
    {
        if ( node->get_name() == name )
            return node;
    }
    return nullptr;
}

ValueConfigNode::ValueConfigNode(BaseConfigNode* parent_node, const Value& val) :
    BaseConfigNode(parent_node), value(val)
{}

BaseConfigNode* ValueConfigNode::get_node(const std::string& name)
{
    return value.is(name.c_str()) and value.has_default() ? this : nullptr;
}

