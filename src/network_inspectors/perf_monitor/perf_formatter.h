//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

//
// PerfFormatter provides an API for PerfTrackers to use for reporting data.
// The basic flow from the perspective of a PerfTracker is:
//
// 1. Call register_section to create a section of stats
//
// 2. Call register_field to insert a field into the most recently created
//    section. Fields should always be pointers to stable locations in memory,
//    as they cannot be updated. Data will be pulled from these pointers when
//    writes occur.
//
// 3. Call finalize_fields to complete section and field registration. This can
//    only be called once per instance.
//
// 4. Set the values desired for fields.
//
// 5. Call write to output the current values in each field.
//
// init_output should be implemented where metadata needs to be written on
// ouput open.
//

#include <ctime>
#include <string>
#include <vector>

#include "framework/counts.h"

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
    PerfFormatter(const std::string& tracker_name)
    { this->tracker_name = tracker_name; }
    virtual ~PerfFormatter() = default;

    virtual bool allow_append()
    { return true; }

    virtual const char* get_extension()
    { return ""; }

    virtual std::string get_tracker_name() final
    { return tracker_name; }

    virtual void register_section(const std::string&);
    virtual void register_field(const std::string&, PegCount*);
    virtual void register_field(const std::string&, const char*);
    virtual void register_field(const std::string&, std::vector<PegCount>*);
    virtual void finalize_fields() {}
    virtual void init_output(FILE*) {}
    virtual void write(FILE*, time_t) = 0;
    virtual void finalize_output(FILE*) {}

protected:
    std::vector<std::vector<FormatterType>> types;
    std::vector<std::vector<FormatterValue>> values;

    std::vector<std::string> section_names;
    std::vector<std::vector<std::string>> field_names;

    unsigned last_section = -1;

private:
    std::string tracker_name;
};

#ifdef UNIT_TEST
#include <map>

class MockFormatter : public PerfFormatter
{
public:
    std::map<std::string, FormatterValue> public_values;

    MockFormatter(const std::string& tracker_name) : PerfFormatter(tracker_name) {}

    void write(FILE*, time_t) override
    {
        for( unsigned i = 0; i < values.size(); i++ )
            for( unsigned j = 0; j < values[i].size(); j++ )
                public_values.insert(std::pair<std::string, FormatterValue>(
                    section_names[i] + "." + field_names[i][j],
                    values[i][j]));
   }
};
#endif

#endif

