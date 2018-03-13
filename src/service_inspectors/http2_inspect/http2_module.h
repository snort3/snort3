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
// http2_module.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_MODULE_H
#define HTTP2_MODULE_H

#include <string>
#include <bitset>

#include "framework/module.h"
#include "profiler/profiler.h"

#include "http2_enum.h"

#define HTTP2_NAME "http2_inspect"
#define HTTP2_HELP "HTTP/2 inspector"

struct Http2ParaList
{
public:
};

class Http2Module : public snort::Module
{
public:
    Http2Module() : snort::Module(HTTP2_NAME, HTTP2_HELP, http2_params) { }
    ~Http2Module() override { delete params; }
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    unsigned get_gid() const override { return Http2Enums::HTTP2_GID; }
    const snort::RuleMap* get_rules() const override { return http2_events; }
    const Http2ParaList* get_once_params()
    {
        Http2ParaList* ret_val = params;
        params = nullptr;
        return ret_val;
    }

    const PegInfo* get_pegs() const override { return peg_names; }
    PegCount* get_counts() const override { return peg_counts; }
    static void increment_peg_counts(Http2Enums::PEG_COUNT counter)
        { peg_counts[counter]++; }
    static void decrement_peg_counts(Http2Enums::PEG_COUNT counter)
        { peg_counts[counter]--; }
    static PegCount get_peg_counts(Http2Enums::PEG_COUNT counter)
        { return peg_counts[counter]; }

    snort::ProfileStats* get_profile() const override;

    static snort::ProfileStats& get_profile_stats()
    { return http2_profile; }

    Usage get_usage() const override
    { return INSPECT; }

private:
    static const snort::Parameter http2_params[];
    static const snort::RuleMap http2_events[];
    Http2ParaList* params = nullptr;
    static const PegInfo peg_names[];
    static THREAD_LOCAL snort::ProfileStats http2_profile;
    static THREAD_LOCAL PegCount peg_counts[];
};

#endif

