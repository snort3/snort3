//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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
// snort_ml_module.h author Brandon Stultz <brastult@cisco.com>

#ifndef SNORT_ML_MODULE_H
#define SNORT_ML_MODULE_H

#include "framework/module.h"
#include "main/thread.h"
#include "profiler/profiler.h"
#include "trace/trace_api.h"

#define SNORT_ML_GID 411
#define SNORT_ML_SID 1

#define SNORT_ML_NAME "snort_ml"
#define SNORT_ML_HELP "machine learning based exploit detector"

enum { TRACE_CLASSIFIER };

struct SnortMLStats
{
    PegCount uri_alerts;
    PegCount client_body_alerts;
    PegCount uri_bytes;
    PegCount client_body_bytes;
    PegCount libml_calls;
};

extern THREAD_LOCAL SnortMLStats snort_ml_stats;
extern THREAD_LOCAL snort::ProfileStats snort_ml_prof;
extern THREAD_LOCAL const snort::Trace* snort_ml_trace;

struct SnortMLConfig
{
    std::string http_param_model_path;
    double http_param_threshold;
    int32_t uri_depth;
    int32_t client_body_depth;
};

class SnortMLModule : public snort::Module
{
public:
    SnortMLModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const SnortMLConfig& get_conf() const
    { return conf; }

    unsigned get_gid() const override
    { return SNORT_ML_GID; }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return INSPECT; }

    snort::ProfileStats* get_profile() const override;

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    SnortMLConfig conf = {};
};

#endif

