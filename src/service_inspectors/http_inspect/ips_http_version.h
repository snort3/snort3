//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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
// ips_http_version.h author Maya Dagon <mdagon@cisco.com>
// Refactored from ips_http.h author Tom Peters <thopeter@cisco.com>

#ifndef IPS_HTTP_VERSION_H
#define IPS_HTTP_VERSION_H

#include "profiler/profiler.h"
#include "framework/ips_option.h"
#include "framework/module.h"

#include "http_enum.h"
#include "ips_http.h"

class HttpVersionRuleOptModule : public HttpRuleOptModule
{
public:
    HttpVersionRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_, const snort::Parameter params[])
        : HttpRuleOptModule(key_, help, rule_opt_index_, cat_, params){}
    snort::ProfileStats* get_profile() const override { return &http_version_ps; }
    static void mod_dtor(snort::Module* m) { delete m; }
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

private:
    friend class HttpVersionIpsOption;
    static THREAD_LOCAL snort::ProfileStats http_version_ps;
    static const int version_size = HttpEnums::VERS__MAX - HttpEnums::VERS__MIN + 1;

    std::bitset<version_size> version_flags;

    bool parse_version_list(snort::Value& v);
};

class HttpVersionIpsOption : public HttpIpsOption
{
public:
    HttpVersionIpsOption(const HttpVersionRuleOptModule* cm) :
        HttpIpsOption(cm, RULE_OPTION_TYPE_OTHER), version_flags(cm->version_flags) {}
    EvalStatus eval(Cursor&, snort::Packet*) override;
    uint32_t hash() const override;
    bool operator==(const snort::IpsOption& ips) const override;

    static IpsOption* opt_ctor(snort::Module* m, OptTreeNode*)
    { return new HttpVersionIpsOption((HttpVersionRuleOptModule*)m); }

    static void opt_dtor(snort::IpsOption* p) { delete p; }

private:
    const std::bitset<HttpVersionRuleOptModule::version_size> version_flags;
};

#endif
