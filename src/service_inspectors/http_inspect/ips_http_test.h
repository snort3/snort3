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
// ips_http_test.h author Maya Dagon <mdagon@cisco.com>

#ifndef IPS_HTTP_TEST_H
#define IPS_HTTP_TEST_H

#include <array>

#include "profiler/profiler.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"

#include "http_enum.h"
#include "http_field.h"
#include "ips_http.h"

enum TestPsIdx { TEST_PSI_HEADER_TEST, TEST_PSI_TRAILER_TEST, TEST_PSI_MAX };

enum NumericValue { NV_UNDEFINED, NV_TRUE, NV_FALSE };

class HttpTestRuleOptModule : public HttpRuleOptModule
{
public:
    HttpTestRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_, TestPsIdx idx_, const snort::Parameter params[])
        : HttpRuleOptModule(key_, help, rule_opt_index_, cat_, params), idx(idx_) {}

    snort::ProfileStats* get_profile() const override
    { return &http_test_ps[idx]; }
  
    static void mod_dtor(snort::Module* m) { delete m; }
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

private:
    friend class HttpTestIpsOption;
    static THREAD_LOCAL std::array<snort::ProfileStats, TEST_PSI_MAX> http_test_ps;
    const TestPsIdx idx;
    snort::RangeCheck check;
    enum NumericValue numeric;
    bool absent;
};

class HttpTestIpsOption : public HttpIpsOption
{
public:
    HttpTestIpsOption(const HttpTestRuleOptModule* cm) :
        HttpIpsOption(cm), idx(cm->idx), check(cm->check),
        numeric(cm->numeric), absent(cm->absent) {}
    EvalStatus eval(Cursor&, snort::Packet*) override;
    uint32_t hash() const override;
    bool operator==(const snort::IpsOption& ips) const override;
    static IpsOption* opt_ctor(snort::Module* m, OptTreeNode*)
        { return new HttpTestIpsOption((HttpTestRuleOptModule*)m); }
    static void opt_dtor(snort::IpsOption* p) { delete p; }

private:
    const TestPsIdx idx;
    const snort::RangeCheck check;
    const enum NumericValue numeric;
    const bool absent;

    IpsOption::EvalStatus eval_header_test(const Field& http_buffer) const;
};

#endif

