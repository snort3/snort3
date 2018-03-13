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

// ssh_module.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef SSH_MODULE_H
#define SSH_MODULE_H

// Interface to the SSH service inspector

#include "framework/module.h"
#include "ssh_config.h"

#define GID_SSH 128

#define SSH_EVENT_RESPOVERFLOW  1
#define SSH_EVENT_CRC32         2
#define SSH_EVENT_SECURECRT     3
//#define SSH_EVENT_PROTOMISMATCH 4 (decommissioned)
#define SSH_EVENT_WRONGDIR      5
#define SSH_EVENT_PAYLOAD_SIZE  6
#define SSH_EVENT_VERSION       7

#define SSH_NAME "ssh"
#define SSH_HELP "ssh inspection"

namespace snort
{struct SnortConfig;

}

extern THREAD_LOCAL SshStats sshstats;
extern THREAD_LOCAL snort::ProfileStats sshPerfStats;

class SshModule : public snort::Module
{
public:
    SshModule();
    ~SshModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_SSH; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }

    SSH_PROTO_CONF* get_data();

private:
    SSH_PROTO_CONF* conf;
};

#endif
