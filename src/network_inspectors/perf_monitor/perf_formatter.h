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

union FormatterValue
{
    PegCount* pc;
    const char* s;
    std::vector<PegCount>* ipc;
};

enum FormatterType : uint8_t
{
    FT_PEG_COUNT,
    FT_STRING,
    FT_IDX_PEG_COUNT
};

class PerfFormatter
{
public:
    PerfFormatter() {};
    virtual ~PerfFormatter() {};
    virtual void register_section(std::string);
    virtual void register_field(std::string, PegCount*);
    virtual void register_field(std::string, const char*);
    virtual void register_field(std::string, std::vector<PegCount>*);
    virtual void finalize_fields(FILE*) = 0;
    virtual void write(FILE*, time_t) = 0;

protected:
    std::vector<std::vector<FormatterType>> types;
    std::vector<std::vector<FormatterValue>> values;
    unsigned last_section = -1;

    virtual void register_field_name(std::string) {};
};
#endif

