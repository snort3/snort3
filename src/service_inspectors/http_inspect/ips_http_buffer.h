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
// ips_http_buffer.h author Maya Dagon <mdagon@cisco.com>
// Refactored from ips_http.h author Tom Peters <thopeter@cisco.com>

#ifndef IPS_HTTP_BUFFER_H
#define IPS_HTTP_BUFFER_H

#include <array>

#include "profiler/profiler.h"
#include "framework/ips_option.h"
#include "framework/module.h"

#include "ips_http.h"

enum BufferPsIdx { BUFFER_PSI_CLIENT_BODY, BUFFER_PSI_COOKIE, BUFFER_PSI_HEADER, BUFFER_PSI_METHOD,
    BUFFER_PSI_RAW_BODY, BUFFER_PSI_RAW_COOKIE, BUFFER_PSI_RAW_HEADER, BUFFER_PSI_RAW_REQUEST,
    BUFFER_PSI_RAW_STATUS, BUFFER_PSI_RAW_TRAILER, BUFFER_PSI_RAW_URI, BUFFER_PSI_STAT_CODE,
    BUFFER_PSI_STAT_MSG, BUFFER_PSI_TRAILER, BUFFER_PSI_TRUE_IP, BUFFER_PSI_URI, BUFFER_PSI_VERSION,
    BUFFER_PSI_JS_DATA, BUFFER_PSI_MAX };

class HttpBufferRuleOptModule : public HttpRuleOptModule
{
public:
    HttpBufferRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_, BufferPsIdx idx_)
        : HttpRuleOptModule(key_, help, rule_opt_index_, cat_), idx(idx_) {}
    HttpBufferRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_, BufferPsIdx idx_, const snort::Parameter params[])
        : HttpRuleOptModule(key_, help, rule_opt_index_, cat_, params), idx(idx_) {}
    snort::ProfileStats* get_profile() const override { return &http_buffer_ps[idx]; }
    static void mod_dtor(snort::Module* m) { delete m; }
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

private:
    friend class HttpBufferIpsOption;
    static THREAD_LOCAL std::array<snort::ProfileStats, BUFFER_PSI_MAX> http_buffer_ps;
    const BufferPsIdx idx;

    // URI related params. These affect the sub_id while parsed.
    // These values are saved to alert on conflicts, only used by ::end
    bool scheme;
    bool host;
    bool port;
    bool path;
    bool query;
    bool fragment;
};

class HttpBufferIpsOption : public HttpIpsOption
{
public:
    HttpBufferIpsOption(const HttpBufferRuleOptModule* cm) :
        HttpIpsOption(cm), idx(cm->idx),
        key(cm->key), fp_buffer_info(cm->rule_opt_index) {}
    EvalStatus eval(Cursor&, snort::Packet*) override;

    static IpsOption* opt_ctor(snort::Module* m, OptTreeNode*)
    { return new HttpBufferIpsOption((HttpBufferRuleOptModule*)m); }

    static void opt_dtor(snort::IpsOption* p) { delete p; }

    snort::CursorActionType get_cursor_type() const override
    { return buffer_info.is_request()? snort::CAT_SET_OTHER : cat; }

private:
    const BufferPsIdx idx;
    const char* const key;
    const HttpBufferInfo fp_buffer_info;
};

#endif
