//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "framework/pdu_section.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"

#include "http_buffer_info.h"
#include "http_enum.h"

class HttpInspect;

class HttpRuleOptModule : public snort::Module
{
public:
    HttpRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_)
        : snort::Module(key_, help), rule_opt_index(rule_opt_index_), key(key_),
          cat(cat_) {}
    HttpRuleOptModule(const char* key_, const char* help, HttpEnums::HTTP_RULE_OPT rule_opt_index_,
        snort::CursorActionType cat_, const snort::Parameter params[])
        : snort::Module(key_, help, params), rule_opt_index(rule_opt_index_),
        key(key_), cat(cat_) {}
    snort::ProfileStats* get_profile() const override = 0;
    static void mod_dtor(snort::Module* m) { delete m; }
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return DETECT; }

protected:
    snort::PduSection pdu_section = snort::PduSection::PS_NONE;
    const HttpEnums::HTTP_RULE_OPT rule_opt_index;
    const char* const key;
    uint64_t sub_id = 0;

private:
    friend class HttpIpsOption;

    const snort::CursorActionType cat;
    uint64_t form = 0;
};

class HttpIpsOption : public snort::IpsOption
{
public:
    HttpIpsOption(const HttpRuleOptModule* cm) :
        snort::IpsOption(cm->key),
        buffer_info(cm->rule_opt_index, cm->sub_id, cm->form),
        cat(cm->sub_id and cm->cat == snort::CAT_SET_FAST_PATTERN ? snort::CAT_SET_SUB_SECTION : cm->cat),
        pdu_section(cm->pdu_section) {}
    snort::CursorActionType get_cursor_type() const override { return cat; }
    EvalStatus eval(Cursor&, snort::Packet*) override = 0;
    uint32_t hash() const override;
    bool operator==(const snort::IpsOption& ips) const override;

    snort::section_flags get_pdu_section(bool) const override;

protected:
    const HttpBufferInfo buffer_info;
    const snort::CursorActionType cat;

    HttpInspect const* eval_helper(snort::Packet* p);

private:
    const snort::PduSection pdu_section;
};

#endif

