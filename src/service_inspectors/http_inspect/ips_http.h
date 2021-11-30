//--------------------------------------------------------------------------
// Copyright (C) 2015-2021 Cisco and/or its affiliates. All rights reserved.
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
// ips_http.h author Tom Peters <thopeter@cisco.com>

#ifndef IPS_HTTP_H
#define IPS_HTTP_H

#include <array>

#include "profiler/profiler.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"

#include "http_buffer_info.h"
#include "http_enum.h"

class HttpInspect;

enum PsIdx { PSI_CLIENT_BODY, PSI_COOKIE, PSI_HEADER, PSI_METHOD, PSI_PARAM,
    PSI_RAW_BODY, PSI_RAW_COOKIE, PSI_RAW_HEADER, PSI_RAW_REQUEST, PSI_RAW_STATUS,
    PSI_RAW_TRAILER, PSI_RAW_URI, PSI_STAT_CODE, PSI_STAT_MSG, PSI_TRAILER,
    PSI_TRUE_IP, PSI_URI, PSI_VERSION, PSI_JS_DATA, PSI_VBA_DATA,
    PSI_RANGE_NUM_HDRS, PSI_RANGE_NUM_TRAILERS, PSI_MAX };

class HttpRuleOptModule : public snort::Module
{
public:
    HttpRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_, PsIdx psi_)
        : snort::Module(key_, help), key(key_), rule_opt_index(rule_opt_index_),
          cat(cat_), psi(psi_) {}
    HttpRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_, PsIdx psi_, const snort::Parameter params[])
        : snort::Module(key_, help, params), key(key_), rule_opt_index(rule_opt_index_),
        cat(cat_), psi(psi_) {}
    snort::ProfileStats* get_profile() const override { return &http_ps[psi]; }
    static void mod_dtor(snort::Module* m) { delete m; }
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return DETECT; }

private:
    friend class HttpIpsOption;
    static THREAD_LOCAL std::array<snort::ProfileStats, PsIdx::PSI_MAX> http_ps;

    struct HttpRuleParaList
    {
    public:
        std::string field;        // provide buffer containing specific header field
        std::string param;        // provide buffer containing specific parameter
        bool nocase;              // case insensitive match
        bool request;             // provide buffer from request not response
        bool with_header;         // provide buffer with a later section than it appears in
        bool with_body;
        bool with_trailer;
        bool scheme;              // provide buffer with one of the six URI subcomponents
        bool host;
        bool port;
        bool path;
        bool query;
        bool fragment;
        snort::RangeCheck range;

        void reset();
    };

    const char* const key;
    const HttpEnums::HTTP_RULE_OPT rule_opt_index;
    const snort::CursorActionType cat;
    const PsIdx psi;

    HttpRuleParaList para_list;
    HttpEnums::InspectSection inspect_section;
    uint64_t sub_id;
    uint64_t form;
};

class HttpIpsOption : public snort::IpsOption
{
public:
    HttpIpsOption(const HttpRuleOptModule* cm) :
        snort::IpsOption(cm->key, RULE_OPTION_TYPE_BUFFER_SET),
        key(cm->key), cat(cm->cat), psi(cm->psi),
        inspect_section(cm->inspect_section),
        buffer_info(cm->rule_opt_index, cm->sub_id, cm->form,
        cm->para_list.param, cm->para_list.nocase), range(cm->para_list.range){}
    snort::CursorActionType get_cursor_type() const override { return cat; }
    EvalStatus eval(Cursor&, snort::Packet*) override;
    uint32_t hash() const override;
    bool operator==(const snort::IpsOption& ips) const override;
    bool retry(Cursor&, const Cursor&) override;
    static IpsOption* opt_ctor(snort::Module* m, OptTreeNode*)
        { return new HttpIpsOption((HttpRuleOptModule*)m); }
    static void opt_dtor(snort::IpsOption* p) { delete p; }

private:
    const char* const key;
    const snort::CursorActionType cat;
    const PsIdx psi;
    const HttpEnums::InspectSection inspect_section;
    HttpBufferInfo buffer_info;
    const snort::RangeCheck range;
};

#endif

