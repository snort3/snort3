/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// config_binding.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/s2l_util.h"

namespace config
{

namespace {

class Binding : public ConversionState
{
public:
    Binding() : ConversionState() {};
    virtual ~Binding() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool Binding::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string binding_type;
    std::string file;
    std::string when;
    std::string val;

    if ((!(data_stream >> file)) ||
        (!(data_stream >> binding_type)))
        return false;

    if (!binding_type.compare("policy_id"))
        when = "policy_id";

    else if (!binding_type.compare("vlan"))
        when = "vlans";

    else if (!binding_type.compare("net"))
        when = "nets";

    else
        return false;


    // we need at least one argument
    if (!util::get_string(data_stream, val, ","))
        return false;

    table_api.open_table("binder");
    table_api.open_table();
    table_api.open_table("when");
    table_api.add_list(when, val);

    while (util::get_string(data_stream, val, ","))
        table_api.add_list(when, val);

    table_api.close_table(); // "when"
    table_api.open_table("use");
    table_api.add_option("file", file);
    table_api.close_table(); // "use"
    table_api.close_table(); // anonymous table
    table_api.close_table(); // "binder"
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor()
{
    return new Binding();
}

static const ConvertMap binding_api =
{
    "binding",
    ctor,
};

const ConvertMap* binding_map = &binding_api;

} // namespace config
