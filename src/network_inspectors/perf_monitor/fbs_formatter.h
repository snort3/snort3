//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// fbs_formatter.h author Carter Waxman <cwaxman@cisco.com>

#ifndef FBS_FORMATTER_H
#define FBS_FORMATTER_H

#include "perf_formatter.h"

#include <flatbuffers/flatbuffers.h>

class FbsFormatter : public PerfFormatter
{
public:
    FbsFormatter(const std::string& tracker_name) : PerfFormatter(tracker_name) {}

    const char* get_extension() override
    { return ".bfbs"; }

    bool allow_append() override
    { return false; }

    void register_section(const std::string&) override;
    void register_field(const std::string&, PegCount*) override;
    void register_field(const std::string&, const char*) override;
    void register_field(const std::string&, std::vector<PegCount>*) override;
    void finalize_fields() override;
    void init_output(FILE*) override;
    void write(FILE*, time_t) override;

private:
    std::string schema;
    std::vector<std::vector<flatbuffers::uoffset_t>> vtable_offsets;

    std::vector<std::string> offset_names;
    std::vector<FormatterType> offset_types;
    std::vector<FormatterValue> offset_values;

    std::vector<std::string> non_offset_names;
    std::vector<PegCount*> non_offset_values;

    void commit_field_reorder();
};

#endif

