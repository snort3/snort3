//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

namespace keywords
{
namespace
{
class Var : public ConversionState
{
public:
    Var(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Var::convert(std::istringstream& data_stream)
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
    else if (ports.front() == '[')
    {
        std::vector<std::string> port_list;
        bool retval = true;

        // FIXIT-M should not be removing the '[' from a PORT_LIST
        if (ports.front() == '[')
            ports.erase(ports.begin());

        if (ports.back() == ']')
            ports.pop_back();

        util::split(ports, ',', port_list);

        for (const std::string& elem : port_list)
            retval = data_api.add_variable(keyword, elem) && retval;

        return retval;
    }
    else
    {
        return data_api.add_variable(keyword, ports);
    }
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new Var(c); }

static const ConvertMap keyword_portvar =
{
    "portvar",
    ctor,
};

static const ConvertMap keyword_ipvar =
{
    "ipvar",
    ctor,
};

static const ConvertMap keyword_var =
{
    "var",
    ctor,
};

const ConvertMap* portvar_map = &keyword_portvar;
const ConvertMap* ipvar_map = &keyword_ipvar;
const ConvertMap* var_map = &keyword_var;
} // namespace keywords

