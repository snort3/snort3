//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

// detection_module.h author Oleksandr Serhiienko <oserhiie@cisco.com>
// based on work by Russ Combs <rucombs@cisco.com>

#ifndef DETECTION_MODULE_H
#define DETECTION_MODULE_H

#include "framework/module.h"

namespace snort
{
class DetectionModule : public Module
{
public:
    DetectionModule();

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    { return pc_names; }

    PegCount* get_counts() const override
    { return (PegCount*) &pc; }

    Usage get_usage() const override
    { return GLOBAL; }

    void set_trace(const Trace*) const override;
    const TraceOption* get_trace_options() const override;

private:
    bool add_service_extension(snort::SnortConfig*);

    std::string service;
    std::vector<std::string> extend_to;
};
}

#endif // DETECTION_MODULE_H
