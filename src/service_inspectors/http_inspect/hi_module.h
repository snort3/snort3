//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// hi_module.cc author Russ Combs <rucombs@cisco.com>

#ifndef HI_MODULE_H
#define HI_MODULE_H

#include <string>

#include "framework/module.h"
#include "hi_ui_config.h"
#include "hi_events.h"

#define GLOBAL_KEYWORD "http_global"
#define SERVER_KEYWORD "http_inspect"

#define GLOBAL_HELP "shared HTTP inspector settings"
#define SERVER_HELP "main HTTP inspector module"

extern THREAD_LOCAL ProfileStats hiPerfStats;

class HttpInspectModule : public Module
{
public:
    HttpInspectModule();
    ~HttpInspectModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_HTTP_CLIENT; }

    const RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    ProfileStats* get_profile() const override;

    HTTPINSPECT_GLOBAL_CONF* get_data();

private:
    HTTPINSPECT_GLOBAL_CONF* config;
};

class HttpServerModule : public Module
{
public:
    HttpServerModule();
    ~HttpServerModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const RuleMap* get_rules() const override;

    unsigned get_gid() const override
    { return GID_HTTP_SERVER; }

    HTTPINSPECT_CONF* get_data();

private:
    HTTPINSPECT_CONF* server;
    std::string methods;
};

#endif

