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
#include "ips_http.h"

enum NumHdrsPsIdx { NUM_HDRS_PSI_HDRS, NUM_HDRS_PSI_TRAILERS, NUM_HDRS_PSI_COOKIES, NUM_HDRS_PSI_MAX };

class HttpNumHdrsRuleOptModule : public HttpRuleOptModule
{
public:
    HttpNumHdrsRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_, NumHdrsPsIdx idx_, const snort::Parameter params[])
        : HttpRuleOptModule(key_, help, rule_opt_index_, cat_, params), idx(idx_) {}

    snort::ProfileStats* get_profile() const override
    { return &http_num_hdrs_ps[idx]; }
  
    static void mod_dtor(snort::Module* m) { delete m; }
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

private:
    friend class HttpNumHdrsIpsOption;
    static THREAD_LOCAL std::array<snort::ProfileStats, NUM_HDRS_PSI_MAX> http_num_hdrs_ps;
    const NumHdrsPsIdx idx;
    snort::RangeCheck range;
};

class HttpNumHdrsIpsOption : public HttpIpsOption
{
public:
    HttpNumHdrsIpsOption(const HttpNumHdrsRuleOptModule* cm) :
        HttpIpsOption(cm), idx(cm->idx), range(cm->range) {}
    EvalStatus eval(Cursor&, snort::Packet*) override;
    uint32_t hash() const override;
    bool operator==(const snort::IpsOption& ips) const override;

    static IpsOption* opt_ctor(snort::Module* m, OptTreeNode*)
    { return new HttpNumHdrsIpsOption((HttpNumHdrsRuleOptModule*)m); }

    static void opt_dtor(snort::IpsOption* p) { delete p; }

private:
    const NumHdrsPsIdx idx;
    const snort::RangeCheck range;
};

#endif

