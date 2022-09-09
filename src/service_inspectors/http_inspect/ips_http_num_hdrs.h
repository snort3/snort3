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
// ips_http_num_hdrs.h author Maya Dagon <mdagon@cisco.com>
// Refactored from ips_http.h author Tom Peters <thopeter@cisco.com>

#ifndef IPS_HTTP_NUM_HDRS_H
#define IPS_HTTP_NUM_HDRS_H

#include <array>

#include "profiler/profiler.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"

#include "http_enum.h"
#include "http_inspect.h"
#include "ips_http.h"

// Base class for all range-based rule options modules
class HttpRangeRuleOptModule : public HttpRuleOptModule
{
public:
    HttpRangeRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        const snort::Parameter params[], snort::ProfileStats& ps_);

    snort::ProfileStats* get_profile() const override { return &ps; }

    static void mod_dtor(snort::Module* m) { delete m; }
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

private:
    snort::ProfileStats& ps;

    friend class HttpRangeIpsOption;
    const char* num_range;
    snort::RangeCheck range;
};

// Base class for all range-based rule options
class HttpRangeIpsOption : public HttpIpsOption
{
public:
    HttpRangeIpsOption(const HttpRangeRuleOptModule* cm) :
        HttpIpsOption(cm), ps(cm->ps), range(cm->range) { }
    EvalStatus eval(Cursor&, snort::Packet*) override;
    uint32_t hash() const override;
    bool operator==(const snort::IpsOption& ips) const override;

    static void opt_dtor(snort::IpsOption* p) { delete p; }

    virtual int32_t get_num(const HttpInspect* hi, snort::Packet* p) = 0;

private:
    snort::ProfileStats& ps;
    const snort::RangeCheck range;
};

// Template class for range-based rule options module
template<HttpEnums::HTTP_RULE_OPT OPT_IDX, HttpEnums::InspectSection SECTION>
class HttpNumRuleOptModule : public HttpRangeRuleOptModule
{
public:
    HttpNumRuleOptModule(const char* key_, const char* help, const snort::Parameter params[])
        : HttpRangeRuleOptModule(key_, help, OPT_IDX, params, ps) { }

    bool begin(const char*, int, snort::SnortConfig*) override
    {
        HttpRangeRuleOptModule::begin(nullptr, 0, nullptr);
        inspect_section = SECTION;
        if (inspect_section == HttpEnums::IS_TRAILER)
        {
            is_trailer_opt = true;
        }
        return true;
    }

private:
    static THREAD_LOCAL snort::ProfileStats ps;
};

template<HttpEnums::HTTP_RULE_OPT OPT_IDX, HttpEnums::InspectSection SECTION>
THREAD_LOCAL snort::ProfileStats HttpNumRuleOptModule<OPT_IDX, SECTION>::ps;

// Template class for range-based rule options
template<int32_t (HttpInspect::* FNC)(snort::Packet*, const HttpBufferInfo&) const>
class HttpNumIpsOption : public HttpRangeIpsOption
{
public:
    using HttpRangeIpsOption::HttpRangeIpsOption;

    static IpsOption* opt_ctor(snort::Module* m, OptTreeNode*)
    { return new HttpNumIpsOption((const HttpRangeRuleOptModule*)m); }

    int32_t get_num(const HttpInspect* hi, snort::Packet* p) override
    { return (hi->*FNC)(p, buffer_info); }
};
#endif

