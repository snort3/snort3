//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// var.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

static bool var_convert(std::istringstream& data_stream, DataApi& data_api,
    bool (*add_var)(const std::string&, const std::string&, DataApi&))
{
    std::string ports; //    cv.print_line(data_stream);
    std::string keyword;

    if (!(data_stream >> keyword))
        return false;

    if (!(data_stream >> ports))
        return false;

    if (isdigit(keyword.front()))
    {
        data_api.add_comment("Bad variable name"
            " - " + keyword + " begins with a number!");
        return false;
    }

    size_t brace_pos = ports.find("[", 0, 1);
    if (brace_pos != std::string::npos)
    {
        std::vector<std::string> port_list;
        bool retval = true;

        if (brace_pos == 0 && ports.back() == ']')
        {
            ports.erase(ports.begin());
            ports.pop_back();
        }

        util::split(ports, ',', port_list);

        for (const std::string& elem : port_list)
            retval = add_var(keyword, elem, data_api) && retval;

        return retval;
    }
    else
    {
        return add_var(keyword, ports, data_api);
    }
}

namespace keywords
{
namespace
{
class NetVar : public ConversionState
{
public:
    NetVar(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override
    {
        return var_convert(data_stream, data_api,
            [](const std::string& name, const std::string& net, DataApi& d_api)
            { return d_api.add_net_variable(name, net); });
    }
};

class PathVar : public ConversionState
{
public:
    PathVar(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override
    {
        return var_convert(data_stream, data_api,
            [](const std::string& name, const std::string& path, DataApi& d_api)
            { return d_api.add_path_variable(name, path); });
    }
};

class PortVar : public ConversionState
{
public:
    PortVar(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override
    {
        return var_convert(data_stream, data_api,
            [](const std::string& name, const std::string& port, DataApi& d_api)
            { return d_api.add_port_variable(name, port); });
    }
};
} // namespace

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor_net_var(Converter& c)
{ return new NetVar(c); }

static ConversionState* ctor_path_var(Converter& c)
{ return new PathVar(c); }

static ConversionState* ctor_port_var(Converter& c)
{ return new PortVar(c); }

static const ConvertMap keyword_portvar =
{
    "portvar",
    ctor_port_var,
};

static const ConvertMap keyword_ipvar =
{
    "ipvar",
    ctor_net_var,
};

static const ConvertMap keyword_var =
{
    "var",
    ctor_path_var,
};

const ConvertMap* portvar_map = &keyword_portvar;
const ConvertMap* ipvar_map = &keyword_ipvar;
const ConvertMap* var_map = &keyword_var;
} // namespace keywords

