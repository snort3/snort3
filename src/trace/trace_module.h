//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
// trace_module.h author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifndef TRACE_MODULE_H
#define TRACE_MODULE_H

#include "framework/module.h"
static std::string DEFAULT_OUTPUT_TRACE = "stdout_trace";

class TraceParser;

class TraceModule : public snort::Module
{
public:
    TraceModule();
    ~TraceModule() override;

    const snort::Command* get_commands() const override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    void generate_params();

private:
    std::vector<snort::Parameter> modules_params;
    std::vector<std::vector<snort::Parameter>> module_ranges;
    std::vector<std::string> modules_help;

    TraceParser* trace_parser = nullptr;
};

#endif  // TRACE_MODULE_H

