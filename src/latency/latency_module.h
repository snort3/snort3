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

// latency_module.h author Joel Cornett <jocornet@cisco.com>

#ifndef LATENCY_MODULE_H
#define LATENCY_MODULE_H

#include "framework/module.h"

class LatencyModule : public snort::Module
{
public:
    LatencyModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    const snort::RuleMap* get_rules() const override;
    unsigned get_gid() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return CONTEXT; }
};

#endif
