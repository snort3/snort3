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

// perf_formatter.h author Carter Waxman <cwaxman@cisco.com>

#ifndef PERF_FORMATTER_H
#define PERF_FORMATTER_H

#include <framework/counts.h>

#include <string>
#include <vector>

typedef unsigned SectionRef;

struct FieldRef
{
    SectionRef section;
    unsigned field;
};

union FormatterValue
{
    PegCount pc;
    double d;
};

enum FormatterType : uint8_t
{
    FT_UNSET,
    FT_PEG_COUNT,
    FT_DOUBLE
};

class PerfFormatter
{
public:
    PerfFormatter() {};
    virtual ~PerfFormatter() {};
    virtual SectionRef register_section(std::string);
    virtual FieldRef register_field(SectionRef, std::string);
    virtual void finalize_fields(FILE*) = 0;
    virtual void set_field(FieldRef, PegCount);
    virtual void set_field(FieldRef, double);
    virtual void write(FILE*, time_t) = 0;
    virtual void clear();

protected:
    std::vector<std::vector<FormatterType>> types;
    std::vector<std::vector<FormatterValue>> values;
};
#endif

