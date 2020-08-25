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
// json_config_output.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "json_config_output.h"

#include "config_data.h"

using namespace snort;

static void dump_value(JsonStream& json, const BaseConfigNode* node)
{
    const Value* value = node->get_value();
    if ( !value )
        return;

    switch ( node->get_type() )
    {
    case Parameter::PT_BOOL:
    case Parameter::PT_IMPLIED:
        value->get_bool() ? json.put_true(node->get_name().c_str()) :
            json.put_false(node->get_name().c_str());
        break;
    case Parameter::PT_INT:
        json.put(node->get_name().c_str(), value->get_long());
        break;
    case Parameter::PT_REAL:
    {
        std::string value_str = value->get_as_string();
        auto pos = value_str.find(".");
        int precision = 0;
        if ( pos != std::string::npos )
            precision = value_str.size() - pos - 1;

        json.put(node->get_name().c_str(), value->get_real(), precision);
        break;
    }
    default:
        json.put(node->get_name().c_str(), value->get_origin_string());
        break;
    }
}

static void dump_modules(JsonStream& json, const BaseConfigNode* node)
{
    Parameter::Type type = node->get_type();
    if ( type == Parameter::PT_LIST )
        json.open_array(node->get_name().c_str());
    else if ( type == Parameter::PT_TABLE )
    {
        std::string name = node->get_name();
        name.empty() ? json.open() : json.open(name.c_str());
    }
    else
        dump_value(json, node);

    for ( const auto n : node->get_children() )
        dump_modules(json, n);

    if ( type == Parameter::PT_LIST )
        json.close_array();
    else if ( type == Parameter::PT_TABLE )
        json.close();
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
        dump_modules(json, config_tree);

    json.close();
    json.close();
}

void JsonTopConfigOutput::dump(const ConfigData& config_data)
{
    json.open();

    for ( const auto config_tree: config_data.config_trees )
        dump_modules(json, config_tree);

    json.close();
}
