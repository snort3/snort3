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

// smtp_module.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef SMTP_MODULE_H
#define SMTP_MODULE_H

// Interface to the SMTP service inspector

#include "framework/module.h"
#include "smtp_config.h"

#define GID_SMTP 124

#define SMTP_COMMAND_OVERFLOW       1
#define SMTP_DATA_HDR_OVERFLOW      2
#define SMTP_RESPONSE_OVERFLOW      3
#define SMTP_SPECIFIC_CMD_OVERFLOW  4
#define SMTP_UNKNOWN_CMD            5
#define SMTP_ILLEGAL_CMD            6
#define SMTP_HEADER_NAME_OVERFLOW   7
#define SMTP_XLINK2STATE_OVERFLOW   8
#define SMTP_DECODE_MEMCAP_EXCEEDED 9
#define SMTP_B64_DECODING_FAILED    10
#define SMTP_QP_DECODING_FAILED     11
// Do not delete or reuse this SID. Commenting this SID as this alert is no longer valid.
//#define SMTP_BITENC_DECODING_FAILED 12
#define SMTP_UU_DECODING_FAILED     13
#define SMTP_AUTH_ABORT_AUTH        14
#define SMTP_AUTH_COMMAND_OVERFLOW  15

#define SMTP_NAME "smtp"
#define SMTP_HELP "smtp inspection"

#define PCMD_LEN         0x0000
#define PCMD_ALT         0x0001
#define PCMD_AUTH        0x0002
#define PCMD_BDATA       0x0004
#define PCMD_DATA        0x0008
#define PCMD_INVALID     0x0010
#define PCMD_NORM        0x0020
#define PCMD_VALID       0x0040

namespace snort
{
struct SnortConfig;
}

extern THREAD_LOCAL snort::ProfileStats smtpPerfStats;
struct SmtpCmd
{
    std::string name;

    uint32_t flags;
    unsigned number;

    SmtpCmd(std::string&, uint32_t, int);
    SmtpCmd(std::string&, int);
};

class SmtpModule : public snort::Module
{
public:
    SmtpModule();
    ~SmtpModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_SMTP; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    SMTP_PROTO_CONF* get_data();
    const SmtpCmd* get_cmd(unsigned idx);

    Usage get_usage() const override
    { return INSPECT; }

private:
    void add_commands(snort::Value&, uint32_t flags);

private:
    SMTP_PROTO_CONF* config;
    std::vector<SmtpCmd*> cmds;
    std::string names;
    int number;
};

#endif
