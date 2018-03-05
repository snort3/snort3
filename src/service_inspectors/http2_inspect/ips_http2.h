//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_http2.h author Tom Peters <thopeter@cisco.com>

#ifndef IPS_HTTP2_H
#define IPS_HTTP2_H

#include <array>

#include "profiler/profiler.h"
#include "framework/ips_option.h"
#include "framework/module.h"

#include "http2_enum.h"

enum PsIdx { PSI_FRAME_DATA, PSI_FRAME_HEADER, PSI_MAX };

class Http2CursorModule : public Module
{
public:
    Http2CursorModule(const char* key_, const char* help, Http2Enums::HTTP2_BUFFER buffer_index_,
        CursorActionType cat_, PsIdx psi_) : Module(key_, help), key(key_),
        buffer_index(buffer_index_), cat(cat_), psi(psi_) {}
    ProfileStats* get_profile() const override { return &http2_ps[psi]; }
    static void mod_dtor(Module* m) { delete m; }
    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return DETECT; }

private:
    friend class Http2IpsOption;
    static THREAD_LOCAL std::array<ProfileStats, PsIdx::PSI_MAX> http2_ps;

    struct Http2RuleParaList
    {
    public:
        void reset();
    };

    const char* const key;
    const Http2Enums::HTTP2_BUFFER buffer_index;
    const CursorActionType cat;
    const PsIdx psi;

    Http2RuleParaList para_list;
};

class Http2IpsOption : public IpsOption
{
public:
    Http2IpsOption(const Http2CursorModule* cm) :
        IpsOption(cm->key, RULE_OPTION_TYPE_BUFFER_SET), key(cm->key),
        buffer_index(cm->buffer_index), cat(cm->cat), psi(cm->psi) {}
    CursorActionType get_cursor_type() const override { return cat; }
    EvalStatus eval(Cursor&, Packet*) override;
    uint32_t hash() const override;
    bool operator==(const IpsOption& ips) const override;
    static IpsOption* opt_ctor(Module* m, OptTreeNode*)
        { return new Http2IpsOption((Http2CursorModule*)m); }
    static void opt_dtor(IpsOption* p) { delete p; }
private:
    const char* const key;
    const Http2Enums::HTTP2_BUFFER buffer_index;
    const CursorActionType cat;
    const PsIdx psi;
};

#endif

