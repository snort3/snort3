//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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
// ips_http_param.h author Maya Dagon <mdagon@cisco.com>
// Refactored from ips_http.h author Tom Peters <thopeter@cisco.com>

#ifndef IPS_HTTP_PARAM_H
#define IPS_HTTP_PARAM_H

#include "profiler/profiler.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "helpers/literal_search.h"

#include "http_param.h"
#include "ips_http.h"


class HttpParamRuleOptModule : public HttpRuleOptModule
{
public:
    HttpParamRuleOptModule(const char* key_, const char* help,
        HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_, const snort::Parameter params[])
        : HttpRuleOptModule(key_, help, rule_opt_index_, cat_, params)
    { search_handle = snort::LiteralSearch::setup(); }

    ~HttpParamRuleOptModule() override
    { snort::LiteralSearch::cleanup(search_handle); }

    snort::ProfileStats* get_profile() const override { return &http_param_ps; }
    static void mod_dtor(snort::Module* m) { delete m; }
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

private:
    friend class HttpParamIpsOption;
    static THREAD_LOCAL snort::ProfileStats http_param_ps;
  
    std::string param;       // provide buffer containing specific parameter
    bool nocase;             // case insensitive match
    snort::LiteralSearch::Handle* search_handle;
};

class HttpParamIpsOption : public HttpIpsOption
{
public:
    HttpParamIpsOption(const HttpParamRuleOptModule* cm)
        : HttpIpsOption(cm), key(cm->key),
          http_param(cm->param, cm->nocase, cm->search_handle) {}
    EvalStatus eval(Cursor&, snort::Packet*) override;
    uint32_t hash() const override;
    bool operator==(const snort::IpsOption& ips) const override;

    static IpsOption* opt_ctor(snort::Module* m, OptTreeNode*)
    { return new HttpParamIpsOption((HttpParamRuleOptModule*)m); }

    static void opt_dtor(snort::IpsOption* p) { delete p; }
    bool retry(Cursor& , const Cursor&) override;
  
    snort::section_flags get_pdu_section(bool) const override;

private:
    const char* const key;
    const HttpParam http_param; 
};

#endif
