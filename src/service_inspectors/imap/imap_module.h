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

// imap_module.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef IMAP_MODULE_H
#define IMAP_MODULE_H

// Interface to the IMAP service inspector

#include "framework/module.h"
#include "imap_config.h"

#define GID_IMAP 141

#define IMAP_UNKNOWN_CMD            1
#define IMAP_UNKNOWN_RESP           2
#define IMAP_B64_DECODING_FAILED    4
#define IMAP_QP_DECODING_FAILED     5
#define IMAP_UU_DECODING_FAILED     7

#define IMAP_NAME "imap"
#define IMAP_HELP "imap inspection"

namespace snort
{
struct SnortConfig;
}

extern THREAD_LOCAL snort::ProfileStats imapPerfStats;

class ImapModule : public snort::Module
{
public:
    ImapModule();
    ~ImapModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_IMAP; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }

    IMAP_PROTO_CONF* get_data();

private:
    IMAP_PROTO_CONF* config;
};

#endif
