//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
//
// dnp3_module.h author Rashmi Pitre <rrp@cisco.com>

#ifndef DNP3_MODULE_H
#define DNP3_MODULE_H

#include "framework/module.h"

#define GID_DNP3  145

namespace snort
{
struct SnortConfig;
}
struct dnp3ProtoConf
{
    bool check_crc;
};

class Dnp3Module : public snort::Module
{
public:
    Dnp3Module();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_DNP3; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }

    void get_data(dnp3ProtoConf&);

private:
    dnp3ProtoConf config;
};

void print_dnp3_conf(dnp3ProtoConf& config);

#endif

