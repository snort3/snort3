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

// ssl_module.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef SSL_MODULE_H
#define SSL_MODULE_H

// Interface to the SSL service inspector

#include "framework/module.h"
#include "ssl_config.h"

#define GID_SSL 137

#define     SSL_INVALID_CLIENT_HELLO               1
#define     SSL_INVALID_SERVER_HELLO               2
#define     SSL_ALERT_HB_REQUEST                   3
#define     SSL_ALERT_HB_RESPONSE                  4

#define SSL_NAME "ssl"
#define SSL_HELP "ssl inspection"

namespace snort
{
struct SnortConfig;
}

extern THREAD_LOCAL snort::ProfileStats sslPerfStats;

class SslModule : public snort::Module
{
public:
    SslModule();
    ~SslModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_SSL; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }

    SSL_PROTO_CONF* get_data();

private:
    SSL_PROTO_CONF* conf;
};

#endif
