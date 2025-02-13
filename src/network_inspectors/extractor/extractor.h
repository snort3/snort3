//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// extractor.h author Anna Norokh <anorokh@cisco.com>

#ifndef EXTRACTOR_H
#define EXTRACTOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "framework/inspector.h"
#include "framework/module.h"
#include "main/snort_config.h"
#include "profiler/profiler.h"

#include "extractor_enums.h"
#include "extractor_service.h"

#define S_NAME "extractor"
#define s_help "extracts protocol specific data"

class ServiceConfig
{
public:
    ServiceConfig() : service(ServiceType::ANY), tenant_id(0) {}
    void clear();

    ServiceType service;
    uint32_t tenant_id;
    std::vector<std::string> on_events;
    std::vector<std::string> fields;
};

struct ExtractorConfig
{
    FormatType formatting = FormatType::CSV;
    std::string output_conn;
    bool pick_by_default = true;
    std::vector<ServiceConfig> protocols;
};

static const PegInfo extractor_pegs[] =
{
    { CountType::SUM, "total_events", "total events processed by extractor" },
    { CountType::END, nullptr, nullptr }
};

struct ExtractorStats
{
    PegCount total_event;
};

class ExtractorReloadSwapper;

extern THREAD_LOCAL ExtractorStats extractor_stats;
extern THREAD_LOCAL snort::ProfileStats extractor_perf_stats;

class ExtractorModule : public snort::Module
{
public:
    ExtractorModule();

    const PegInfo* get_pegs() const override
    { return extractor_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&extractor_stats; }

    snort::ProfileStats* get_profile() const override
    { return &extractor_perf_stats; }

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value& v, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

    const ExtractorConfig& get_config()
    { return extractor_config; }

private:
    void store(snort::Value& val, std::vector<std::string>& dst);
    void commit_config();

    ExtractorConfig extractor_config;
    ServiceConfig service_config;
};

class Extractor : public snort::Inspector
{
public:
    Extractor(ExtractorModule*);
    ~Extractor() override;

    bool configure(snort::SnortConfig*) override;

    void show(const snort::SnortConfig*) const override;

    void tinit() override;
    void tterm() override;
    void install_reload_handler(snort::SnortConfig*) override;

    snort::SnortConfig& get_snort_config() const
    { return snort_config ? *snort_config : *snort::SnortConfig::get_main_conf(); }

    bool get_default_filter() const
    { return cfg.pick_by_default; }

private:
    snort::SnortConfig* snort_config = nullptr;
    ExtractorConfig cfg;
    std::vector<ExtractorService*> services;
    static THREAD_LOCAL ExtractorLogger* logger;

    friend class ExtractorReloadSwapper;
};

#endif
