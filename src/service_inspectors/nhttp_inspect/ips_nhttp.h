//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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
// ips_nhttp.h author Tom Peters <thopeter@cisco.com>

#ifndef IPS_NHTTP_H
#define IPS_NHTTP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <array>

#include "main/snort_types.h"
#include "profiler/profiler.h"
#include "framework/ips_option.h"
#include "framework/module.h"

#include "nhttp_enum.h"

enum PsIdx { PSI_URI, PSI_CLIENT_BODY, PSI_METHOD, PSI_COOKIE, PSI_STAT_CODE, PSI_STAT_MSG,
    PSI_RAW_URI, PSI_RAW_HEADER, PSI_RAW_COOKIE, PSI_HEADER, PSI_VERSION, PSI_TRAILER,
    PSI_RAW_TRAILER, PSI_RAW_REQUEST, PSI_RAW_STATUS, PSI_MAX };

class NHttpCursorModule : public Module
{
public:
    NHttpCursorModule(const char* key_, const char* help, NHttpEnums::NHTTP_BUFFER buffer_index_,
        CursorActionType cat_, PsIdx psi_) : Module(key_, help), key(key_),
        buffer_index(buffer_index_), cat(cat_), psi(psi_) {}
    NHttpCursorModule(const char* key_, const char* help, NHttpEnums::NHTTP_BUFFER buffer_index_,
        CursorActionType cat_, PsIdx psi_, const Parameter params[]) : Module(key_, help, params),
        key(key_), buffer_index(buffer_index_), cat(cat_), psi(psi_) {}
    ProfileStats* get_profile() const override { return &http_ps[psi]; }
    static void mod_dtor(Module* m) { delete m; }
    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

private:
    friend class NHttpIpsOption;
    static THREAD_LOCAL std::array<ProfileStats, PsIdx::PSI_MAX> http_ps;

    struct NHttpRuleParaList
    {
    public:
        std::string field;        // provide buffer containing specific header field
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

        void reset();
    };

    const char* const key;
    const NHttpEnums::NHTTP_BUFFER buffer_index;
    const CursorActionType cat;
    const PsIdx psi;

    NHttpRuleParaList para_list;
    NHttpEnums::InspectSection inspect_section;
    uint64_t sub_id;
    uint64_t form;
};

class NHttpIpsOption : public IpsOption
{
public:
    NHttpIpsOption(const NHttpCursorModule* cm) :
        IpsOption(cm->key, RULE_OPTION_TYPE_BUFFER_SET), key(cm->key),
        buffer_index(cm->buffer_index), cat(cm->cat), psi(cm->psi),
        inspect_section(cm->inspect_section), sub_id(cm->sub_id), form(cm->form) {}
    CursorActionType get_cursor_type() const override { return cat; }
    int eval(Cursor&, Packet*) override;
    uint32_t hash() const override;
    bool operator==(const IpsOption& ips) const override;
    static IpsOption* opt_ctor(Module* m, OptTreeNode*)
        { return new NHttpIpsOption((NHttpCursorModule*)m); }
    static void opt_dtor(IpsOption* p) { delete p; }
private:
    const char* const key;
    const NHttpEnums::NHTTP_BUFFER buffer_index;
    const CursorActionType cat;
    const PsIdx psi;
    const NHttpEnums::InspectSection inspect_section;
    const uint64_t sub_id;
    const uint64_t form;
};

#endif

