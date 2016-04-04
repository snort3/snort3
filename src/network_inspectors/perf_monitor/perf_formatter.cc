//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// perf_formatter.cc author Carter Waxman <cwaxman@cisco.com>

#include "perf_formatter.h"

using namespace std;

SectionRef PerfFormatter::register_section(string)
{
    types.push_back(vector<FormatterType>());
    values.push_back(vector<FormatterValue>());

    return types.size() - 1;
}

FieldRef PerfFormatter::register_field(SectionRef section, string)
{
    FieldRef ret;
    FormatterValue fv;
    fv.pc = 0;

    values[section].push_back(fv);
    types[section].push_back(FT_UNSET);
    
    ret.section = section;
    ret.field = values[section].size() - 1;

    return ret;
}

void PerfFormatter::set_field(FieldRef ref, PegCount val)
{
    FormatterValue fv;

    fv.pc = val;
    values[ref.section][ref.field] = fv;
    types[ref.section][ref.field] = FT_PEG_COUNT;
}

void PerfFormatter::set_field(FieldRef ref, double val)
{
    FormatterValue fv;

    fv.d = val;
    values[ref.section][ref.field] = fv;
    types[ref.section][ref.field] = FT_DOUBLE;
}

void PerfFormatter::clear()
{
    for(unsigned i = 0; i < types.size(); i++)
        for(unsigned j = 0; j < types[i].size(); j++)
            types[i][j] = FT_UNSET;
}


