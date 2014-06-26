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
// dt_rule.cc author Josh Rosenbaum <jorosenba@cisco.com>


#include "data/dt_rule.h"


Rule::Rule()
{
    bad_rule = false;
    num_hdr_data = 0;
}

Rule::~Rule(){};


bool Rule::add_hdr_data(std::string data)
{
    if (num_hdr_data < hdr_data.size())
    {
        hdr_data[num_hdr_data] = data;
        num_hdr_data++;
        return true;
    }
    else
    {
        bad_rule = true;
        return false;
    }
}


std::ostream &operator<<( std::ostream& out, const Rule &r)
{
    std::string built_string = "";

    for(int i = 0; i < r.num_hdr_data; i++)
    {
        if (!r.hdr_data.empty())
            built_string += r.hdr_data[i];
    }



    return out;
}
