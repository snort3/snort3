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
// var.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"


namespace keywords
{

namespace {

class Var : public ConversionState
{
public:
    Var(Converter* cv, LuaData* ld) : ConversionState(cv, ld){}
    virtual ~Var() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace

#include <iostream>
bool Var::convert(std::istringstream& data_stream)
{
    std::string ports;//    cv->print_line(data_stream);
    std::string keyword;

    if (!(data_stream >> keyword))
        return false;

    if(!(data_stream >> ports))
        return false;

    if (isdigit(keyword.front()))
    {
        ld->add_comment("Bad variable name"
            " - " + keyword + " begins with a number!");
        return false;
    }
    else if(ports.front() == '[')
    {
        std::vector<std::string> port_list;
        bool retval = true;

        if(ports.front() == '[')
            ports.erase(ports.begin());
        
        if(ports.back() == ']')
            ports.pop_back();
    
        util::split(ports, ',', port_list);

        for(std::string elem : port_list)
            retval = ld->add_variable(keyword, elem) && retval;

        return retval;
    }
    else
    {
        return ld->add_variable(keyword, ports);
    }
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Var(cv, ld);
}

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
