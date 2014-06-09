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
// portvar.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>
#include <iomanip>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"


namespace {

class PortVar : public ConversionState
{
public:
    PortVar(Converter* cv);
    virtual ~PortVar() {};
    virtual bool convert(std::stringstream& data, bool last_line, std::ofstream&);

private:
    bool first_line;

};

} // namespace


PortVar::PortVar(Converter* cv) : ConversionState(cv)
{
    first_line = true;
}

bool PortVar::convert(std::stringstream& data_stream, bool last_line, std::ofstream& out)
{
    std::string keyword;
    std::string ports;//    converter->print_line(data_stream);

    if (first_line)
    {
        if (data_stream >> keyword)
        {
            out << keyword << " = " << std::endl;
            out << "[[" << std::endl;

            first_line = false;
        }
        else
        {
            return false;
        }
    }

    if(!(data_stream >> ports))
        return false;

    if(ports.front() == '[' && ports.back() == ']')
    {
        std::vector<std::string> port_list;
        int count = 11;

        ports.erase(ports.begin());
        ports.pop_back();
        util::split(ports, ',', port_list);

        for(std::string elem : port_list)
        {
            if(count >= 11)
            {
                if (elem.compare(*port_list.begin()))
                    out << std::endl;
                out << "   "; // fourth space added below
                count = 0;
            }

            if(elem.front() == '$')
                elem.erase(elem.begin());

            out << ' ' << std::setw(5) << std::left << elem;
            count++;
        }
    }
    else
    {
        out << "    " <<  std::setw(5) << std::left << ports;
    }

    if(last_line)
        out << std::endl << "]]" << std::endl;

    return true;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv)
{
    return new PortVar(cv);
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
