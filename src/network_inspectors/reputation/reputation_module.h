//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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

// reputation_module.h author Bhagya Tholpady <bbantwal@cisco.com>

#ifndef REPUTATION_MODULE_H
#define REPUTATION_MODULE_H

// Interface to the REPUTATION network inspector

#include "framework/module.h"
#include "reputation_config.h"

#define GID_REPUTATION 136

#define REPUTATION_EVENT_BLACKLIST       1
#define REPUTATION_EVENT_WHITELIST       2
#define REPUTATION_EVENT_MONITOR         3

#define REPUTATION_NAME "reputation"
#define REPUTATION_HELP "reputation inspection"

struct SnortConfig;

extern THREAD_LOCAL ProfileStats reputationPerfStats;
extern unsigned long total_duplicates;
extern unsigned long total_invalids;

class ReputationModule : public Module
{
public:
    ReputationModule();
    ~ReputationModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_REPUTATION; }

    const RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    ProfileStats* get_profile() const override;

    ReputationConfig* get_data();

private:
    ReputationConfig* conf;
};

#endif

