//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// ftp_module.h author Russ Combs <rucombs@cisco.com>

#ifndef FTP_MODULE_H
#define FTP_MODULE_H

#include "framework/module.h"
#include "ftpp_ui_config.h"

#define GID_FTP 125

#define FTP_TELNET_CMD                   1
#define FTP_INVALID_CMD                  2
#define FTP_PARAMETER_LENGTH_OVERFLOW    3
#define FTP_MALFORMED_PARAMETER          4
#define FTP_PARAMETER_STR_FORMAT         5
#define FTP_RESPONSE_LENGTH_OVERFLOW     6
#define FTP_ENCRYPTED                    7
#define FTP_BOUNCE                       8
#define FTP_EVASIVE_TELNET_CMD           9

namespace snort
{
struct SnortConfig;
}

extern THREAD_LOCAL snort::ProfileStats ftpPerfStats;

//-------------------------------------------------------------------------

struct BounceTo
{
    std::string address;
    Port low;
    Port high;

    BounceTo(std::string& address, Port lo, Port hi);
};

class FtpClientModule : public snort::Module
{
public:
    FtpClientModule();
    ~FtpClientModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    FTP_CLIENT_PROTO_CONF* get_data();
    const BounceTo* get_bounce(unsigned idx);

    Usage get_usage() const override
    { return INSPECT; }

private:
    FTP_CLIENT_PROTO_CONF* conf;
    std::vector<BounceTo*> bounce_to;

    std::string address;
    Port port, last_port;
};

//-------------------------------------------------------------------------

#define CMD_LEN    0x0000
#define CMD_ALLOW  0x0001
#define CMD_CHECK  0x0002
#define CMD_DATA   0x0004
#define CMD_XFER   0x0008
#define CMD_PUT    0x0010
#define CMD_GET    0x0020
#define CMD_LOGIN  0x0040
#define CMD_ENCR   0x0080
#define CMD_DIR    0x0100
#define CMD_VALID  0x0200
#define CMD_REST   0x0400

struct FtpCmd
{
    std::string name;
    std::string format;

    uint32_t flags;
    unsigned number;

    FtpCmd(std::string&, uint32_t, int);
    FtpCmd(std::string&, std::string&, int);
};

class FtpServerModule : public snort::Module
{
public:
    FtpServerModule();
    ~FtpServerModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_FTP; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }

    FTP_SERVER_PROTO_CONF* get_data();
    const FtpCmd* get_cmd(unsigned idx);

private:
    void add_commands(snort::Value&, uint32_t flags, int num = 0);

private:
    FTP_SERVER_PROTO_CONF* conf;
    std::vector<FtpCmd*> cmds;
    std::string names;
    std::string format;
    int number;
};

#endif

