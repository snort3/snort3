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
#include "converter.h"
#include "snort2lua_util.h"


namespace {

class Var : public ConversionState
{
public:
    Var(Converter* cv);
    virtual ~Var() {};
    virtual bool convert(std::stringstream& data);

private:
    bool first_line;
    bool is_port_list;
    std::string keyword;
};

} // namespace


Var::Var(Converter* cv) : ConversionState(cv)
{
    first_line = true;
    is_port_list = false;
}

bool Var::convert(std::stringstream& data_stream)
{
    std::string ports;//    cv->print_line(data_stream);

    if (first_line)
        if (!(data_stream >> keyword))
            return false;

    if(!(data_stream >> ports))
        return false;

    if(is_port_list || ports.front() == '[')
    {
        std::vector<std::string> port_list;
        is_port_list = true;
        bool retval = true;

        if(ports.front() == '[')
            ports.erase(ports.begin());
        
        if(ports.back() == ']')
            ports.pop_back();
    
        util::split(ports, ',', port_list);

        for(std::string elem : port_list)
            retval = cv->add_variable(keyword, elem) && retval;

        return retval;
    }
    else
    {
        return cv->add_variable(keyword, ports);
    }
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv)
{
    return new Var(cv);
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
