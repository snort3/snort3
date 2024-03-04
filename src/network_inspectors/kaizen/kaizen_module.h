//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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
// kaizen_module.h author Brandon Stultz <brastult@cisco.com>

#ifndef KAIZEN_MODULE_H
#define KAIZEN_MODULE_H

#include "framework/module.h"
#include "main/thread.h"
#include "profiler/profiler.h"
#include "trace/trace_api.h"

#define KZ_GID 411
#define KZ_SID 1

#define KZ_NAME "snort_ml"
#define KZ_HELP "machine learning based exploit detector"

enum { TRACE_CLASSIFIER };

struct KaizenStats
{
    PegCount uri_alerts;
    PegCount client_body_alerts;
    PegCount uri_bytes;
    PegCount client_body_bytes;
    PegCount libml_calls;
};

extern THREAD_LOCAL KaizenStats kaizen_stats;
extern THREAD_LOCAL snort::ProfileStats kaizen_prof;
extern THREAD_LOCAL const snort::Trace* kaizen_trace;

struct KaizenConfig
{
    std::string http_param_model_path;
    double http_param_threshold;
    int32_t uri_depth;
    int32_t client_body_depth;
};

class KaizenModule : public snort::Module
{
public:
    KaizenModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const KaizenConfig& get_conf() const
    { return conf; }

    unsigned get_gid() const override
    { return KZ_GID; }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return INSPECT; }

    snort::ProfileStats* get_profile() const override;

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    KaizenConfig conf = {};
};

#endif

