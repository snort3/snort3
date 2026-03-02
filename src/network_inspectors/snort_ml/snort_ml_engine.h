//--------------------------------------------------------------------------
// Copyright (C) 2023-2026 Cisco and/or its affiliates. All rights reserved.
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
// snort_ml_engine.h author Vitalii Horbatov <vhorbato@cisco.com>
//                   author Brandon Stultz <brastult@cisco.com>

#ifndef SNORT_ML_ENGINE_H
#define SNORT_ML_ENGINE_H

#ifdef HAVE_LIBML
#include <libml.h>
#endif

#include <memory>
#include <unordered_map>
#include <utility>

#include "framework/inspector.h"
#include "framework/module.h"
#include "hash/lru_cache_local.h"
#include "search_engines/search_tool.h"

#define SNORT_ML_ENGINE_NAME "snort_ml_engine"
#define SNORT_ML_ENGINE_HELP "configure machine learning engine settings"
#define SNORT_ML_ENGINE_USE  Module::GLOBAL

// Mock BinaryClassifierSet for tests if LibML is absent
#ifndef HAVE_LIBML
namespace libml
{

class BinaryClassifierSet
{
public:
    bool build(const std::vector<std::string>& models)
    {
        if (!models.empty())
            pattern = models[0];

        return pattern != "error";
    }

    bool run(const char* ptr, size_t len, float& out)
    {
        std::string data(ptr, len);
        out = data.find(pattern) == std::string::npos ? 0.0f : 1.0f;
        return pattern != "fail";
    }

private:
    std::string pattern;
};

}
#endif

struct SnortMLEngineStats : public LruCacheLocalStats
{
    PegCount filter_searches;
    PegCount filter_matches;
    PegCount filter_allows;
    PegCount libml_calls;
};

typedef LruCacheLocal<uint64_t, float, std::hash<uint64_t>> SnortMLCache;
typedef std::unordered_map<std::string, bool> SnortMLFilterMap;

struct SnortMLContext
{
    libml::BinaryClassifierSet classifiers;
    std::unique_ptr<SnortMLCache> cache;
};

struct SnortMLEngineConfig
{
    std::string http_param_model_path;
    std::vector<std::string> http_param_models;
    SnortMLFilterMap http_param_filters;
    bool has_allow = false;
    size_t cache_memcap = 0;
};

struct SnortMLSearch
{
    bool match = false;
    bool allow = false;
    bool has_allow = false;
};

class SnortMLEngineModule : public snort::Module
{
public:
    SnortMLEngineModule();

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return GLOBAL; }

    SnortMLEngineConfig get_config()
    {
        SnortMLEngineConfig out;
        std::swap(conf, out);
        return out;
    }

private:
    SnortMLEngineConfig conf;
};

class SnortMLEngine : public snort::Inspector
{
public:
    SnortMLEngine(SnortMLEngineConfig c) : conf(std::move(c)) {}
    ~SnortMLEngine() override
    { delete mpse; }

    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;

    void tinit() override;
    void tterm() override;

    void install_reload_handler(snort::SnortConfig*) override;

    bool scan(const char*, const size_t, float&) const;

private:
    bool read_models();
    bool read_model(const std::string&);

    SnortMLEngineConfig conf;
    snort::SearchTool* mpse = nullptr;
};

#endif
