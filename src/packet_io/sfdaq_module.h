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

// sfdaq_module.h author Michael Altizer <mialtize@cisco.com>

#ifndef SFDAQ_MODULE_H
#define SFDAQ_MODULE_H

#include "framework/module.h"

namespace snort
{
struct SnortConfig;
}
struct SFDAQConfig;
struct SFDAQInstanceConfig;

class SFDAQModule : public snort::Module
{
public:
    SFDAQModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    void prep_counts() override;

    bool counts_need_prep() const override
    { return true; }

    Usage get_usage() const override
    { return GLOBAL; }

private:
    SFDAQConfig* config;
    SFDAQInstanceConfig* instance_config;
    int instance_id;
};

#endif
