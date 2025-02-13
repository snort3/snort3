//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
// trace_parser.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef TRACE_PARSER_H
#define TRACE_PARSER_H

#include <map>
#include <string>

#include "packet_io/packet_constraints.h"

namespace snort
{
class Module;
class Value;
}

class TraceConfig;

class TraceParser
{
public:
    TraceParser(TraceConfig&);

    bool set_traces(const std::string& option_name, const snort::Value& val);
    bool set_constraints(const snort::Value& val);

    void finalize_constraints();
    void clear_traces();
    void clear_constraints();

    void reset_configured_trace_options();

    TraceConfig& get_trace_config() const
    { return trace_config; }

private:
    void init_configured_trace_options();

private:
    TraceConfig& trace_config;
    snort::PacketConstraints parsed_constraints{};

    static std::map<std::string, std::map<std::string, bool>> s_configured_trace_options;
};

#endif // TRACE_PARSER_H

