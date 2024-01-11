//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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

// cip_module.h author Jian Wu <jiawu2@cisco.com>

#ifndef CIP_MODULE_H
#define CIP_MODULE_H

// Interface to the CIP service inspector

#include "framework/module.h"

#include "cip_definitions.h"

#define GID_CIP 148

#define CIP_MALFORMED         1
#define CIP_NON_CONFORMING    2
#define CIP_CONNECTION_LIMIT  3
#define CIP_REQUEST_LIMIT     4

#define CIP_NAME "cip"
#define CIP_HELP "cip inspection"

extern THREAD_LOCAL snort::ProfileStats cip_perf_stats;

class CipModule : public snort::Module
{
public:
    CipModule();
    ~CipModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_CIP; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

    CipProtoConf* get_data();

private:
    CipProtoConf* conf;
    std::string embedded_path;
};

#endif

