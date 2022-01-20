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
// json_config_output.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "json_config_output.h"

#include "config_data.h"

using namespace snort;

static void dump_value(JsonStream& json, const char* node_name, const BaseConfigNode* node)
{
    const Value* value = node->get_value();
    if ( !value )
        return;

    switch ( node->get_type() )
    {
    case Parameter::PT_BOOL:
    case Parameter::PT_IMPLIED:
        value->get_bool() ? json.put_true(node_name) :
            json.put_false(node_name);
        break;
    case Parameter::PT_INT:
        json.put(node_name, value->get_int64());
        break;
    case Parameter::PT_REAL:
    {
        std::string value_str = value->get_as_string();
        auto pos = value_str.find(".");
        int precision = 0;
        if ( pos != std::string::npos )
            precision = value_str.size() - pos - 1;

        json.put(node_name, value->get_real(), precision);
        break;
    }
    default:
        json.put(node_name, value->get_origin_string());
        break;
    }
}

static void dump_tree(JsonStream& json, const BaseConfigNode* node, bool list_node = false)
{
    Parameter::Type node_type = node->get_type();
    const std::string node_name = node->get_name();
    const char* node_name_cstr = nullptr;

    if ( !list_node )
        node_name_cstr = node_name.c_str();

    if ( node_type == Parameter::PT_TABLE )
    {
        json.open(node_name_cstr);
        for ( const auto n : node->get_children() )
            dump_tree(json, n);
        json.close();
    }
    else if ( node_type == Parameter::PT_LIST )
    {
        json.open_array(node_name_cstr);
        for ( const auto n : node->get_children() )
            dump_tree(json, n, true);
        json.close_array();
    }
    else
        dump_value(json, node_name_cstr, node);
}

JsonAllConfigOutput::JsonAllConfigOutput() :
    ConfigOutput(), json(std::cout)
{ json.open_array(); }

JsonAllConfigOutput::~JsonAllConfigOutput()
{ json.close_array(); }

void JsonAllConfigOutput::dump(const ConfigData& config_data)
{
    json.open();
    json.put("filename", config_data.file_name);
    json.open("config");

    for ( const auto config_tree: config_data.config_trees )
        dump_tree(json, config_tree);

    json.close();
    json.close();
}

void JsonTopConfigOutput::dump(const ConfigData& config_data)
{
    json.open();

    for ( const auto config_tree: config_data.config_trees )
        dump_tree(json, config_tree);

    json.close();
}
