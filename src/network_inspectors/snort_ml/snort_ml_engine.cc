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
// snort_ml_engine.cc author Vitalii Horbatov <vhorbato@cisco.com>
//                    author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_ml_engine.h"

#include <cassert>
#include <cstring>
#include <fstream>

#include "framework/decode_data.h"
#include "hash/fnv.h"
#include "helpers/directory.h"
#include "log/messages.h"
#include "main/reload_tuner.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "parser/parse_conf.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL SnortMLEngineStats snort_ml_engine_stats;
static THREAD_LOCAL SnortMLContext* snort_ml_ctx = nullptr;

static SnortMLContext* create_context(const SnortMLEngineConfig& conf)
{
    SnortMLContext* ctx = new SnortMLContext();

    if (!ctx->classifiers.build(conf.http_param_models))
    {
        ErrorMessage("Could not build classifiers.\n");
        return ctx;
    }

    if (conf.cache_memcap > 0)
    {
        ctx->cache = make_unique<SnortMLCache>(conf.cache_memcap,
            snort_ml_engine_stats);
    }

    return ctx;
}

//--------------------------------------------------------------------------
// module
//--------------------------------------------------------------------------

static const Parameter filter_param[] =
{
    { "filter_pattern", Parameter::PT_STRING, nullptr, nullptr,
      "pattern that triggers ML classification" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ignore_param[] =
{
    { "ignore_pattern", Parameter::PT_STRING, nullptr, nullptr,
      "pattern that skips ML classification" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter snort_ml_engine_params[] =
{
    { "http_param_model", Parameter::PT_STRING, nullptr, nullptr,
      "path to model file(s)" },

    { "http_param_filter", Parameter::PT_LIST, filter_param, nullptr,
      "list of patterns that trigger ML classification" },

    { "http_param_ignore", Parameter::PT_LIST, ignore_param, nullptr,
      "list of patterns that skip ML classification" },

    { "cache_memcap", Parameter::PT_INT, "0:maxSZ", "0",
      "maximum memory for verdict cache in bytes, 0 = disabled" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo peg_names[] =
{
    LRU_CACHE_LOCAL_PEGS("snort_ml_engine"),
    { CountType::SUM, "filter_searches", "total filter searches" },
    { CountType::SUM, "filter_matches", "total filter matches" },
    { CountType::SUM, "filter_allows", "total filter allows" },
    { CountType::SUM, "libml_calls", "total libml calls" },
    { CountType::END, nullptr, nullptr }
};

SnortMLEngineModule::SnortMLEngineModule()
    : Module(SNORT_ML_ENGINE_NAME, SNORT_ML_ENGINE_HELP, snort_ml_engine_params) {}

bool SnortMLEngineModule::begin(const char* fqn, int, SnortConfig*)
{
    if (!strcmp(SNORT_ML_ENGINE_NAME, fqn))
        conf = {};

    return true;
}

bool SnortMLEngineModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("http_param_model"))
        conf.http_param_model_path = v.get_string();

    else if (v.is("filter_pattern"))
        conf.http_param_filters[v.get_string()] = true;

    else if (v.is("ignore_pattern"))
    {
        conf.http_param_filters[v.get_string()] = false;
        conf.has_allow = true;
    }

    else if (v.is("cache_memcap"))
        conf.cache_memcap = v.get_size();

    return true;
}

const PegInfo* SnortMLEngineModule::get_pegs() const
{ return peg_names; }

PegCount* SnortMLEngineModule::get_counts() const
{ return reinterpret_cast<PegCount*>(&snort_ml_engine_stats); }

//--------------------------------------------------------------------------
// reload tuner
//--------------------------------------------------------------------------

class SnortMLReloadTuner : public snort::ReloadResourceTuner
{
public:
    explicit SnortMLReloadTuner(const SnortMLEngineConfig& c) : conf(c) {}
    ~SnortMLReloadTuner() override = default;

    const char* name() const override
    { return "SnortMLReloadTuner"; }

    bool tinit() override
    {
        delete snort_ml_ctx;
        snort_ml_ctx = create_context(conf);
        return false;
    }

    bool tune_packet_context() override
    { return true; }

    bool tune_idle_context() override
    { return true; }

private:
    const SnortMLEngineConfig& conf;
};

//--------------------------------------------------------------------------
// inspector
//--------------------------------------------------------------------------

bool SnortMLEngine::configure(SnortConfig*)
{
    if (!read_models())
        return false;

    libml::BinaryClassifierSet classifiers;

    if (!classifiers.build(conf.http_param_models))
    {
        ParseError("Could not build classifiers.");
        return false;
    }

    if (!conf.http_param_filters.empty())
    {
        mpse = new SearchTool;

        for (auto& f : conf.http_param_filters)
            mpse->add(f.first.c_str(), f.first.size(), (void*)&f);

        mpse->prep();
    }

    return true;
}

void SnortMLEngine::show(const SnortConfig*) const
{
    ConfigLogger::log_value("http_param_model", conf.http_param_model_path.c_str());
    ConfigLogger::log_value("cache_memcap", conf.cache_memcap);
}

bool SnortMLEngine::read_models()
{
    const char* hint = conf.http_param_model_path.c_str();
    string path;

    if (!get_config_file(hint, path))
    {
        ParseError("snort_ml_engine: could not read model file(s): %s", hint);
        return false;
    }

    if (!is_directory_path(path))
    {
        if (!read_model(path))
        {
            ParseError("snort_ml_engine: could not read model file: %s", path.c_str());
            return false;
        }

        return true;
    }

    Directory model_dir(path.c_str());

    if (model_dir.error_on_open())
    {
        ParseError("snort_ml_engine: could not read model dir: %s", path.c_str());
        return false;
    }

    while (const char* f = model_dir.next())
    {
        if (!read_model(f))
        {
            ParseError("snort_ml_engine: could not read model: %s", f);
            return false;
        }
    }

    if (conf.http_param_models.empty())
    {
        ParseError("snort_ml_engine: no models found");
        return false;
    }

    return true;
}

bool SnortMLEngine::read_model(const string& path)
{
    size_t size = 0;

    if (!get_file_size(path, size))
        return false;

    ifstream file(path, ios::binary);

    if (!file.is_open() || size == 0)
        return false;

    string buffer(size, '\0');
    file.read(&buffer[0], streamsize(size));

    conf.http_param_models.push_back(std::move(buffer));
    return true;
}

void SnortMLEngine::tinit()
{ snort_ml_ctx = create_context(conf); }

void SnortMLEngine::tterm()
{
    delete snort_ml_ctx;
    snort_ml_ctx = nullptr;
}

void SnortMLEngine::install_reload_handler(SnortConfig* sc)
{ sc->register_reload_handler(new SnortMLReloadTuner(conf)); }

static int filter_match_callback(void* f, void*, int, void* s, void*)
{
    auto filter = reinterpret_cast<const pair<string, bool>*>(f);
    auto search = reinterpret_cast<SnortMLSearch*>(s);

    search->match = true;
    search->allow |= !filter->second;

    if (search->has_allow && !search->allow)
        return 0;

    return 1;
}

bool SnortMLEngine::scan(const char* buf, const size_t len, float& out) const
{
    if (!snort_ml_ctx)
        return false;

    if (mpse)
    {
        snort_ml_engine_stats.filter_searches++;

        SnortMLSearch search;
        search.has_allow = conf.has_allow;

        mpse->find_all(buf, len, filter_match_callback,
            false, (void*)&search);

        if (!search.match)
            return false;

        snort_ml_engine_stats.filter_matches++;

        if (search.allow)
        {
            snort_ml_engine_stats.filter_allows++;
            return false;
        }
    }

    float res = 0;
    bool is_new = true;

    float& result = (snort_ml_ctx->cache) ?
        snort_ml_ctx->cache->find_else_create(fnv1a(buf, len), &is_new) : res;

    if (is_new)
    {
        snort_ml_engine_stats.libml_calls++;

        if (!snort_ml_ctx->classifiers.run(buf, len, result))
            return false;
    }

    out = result;
    return true;
}

//--------------------------------------------------------------------------
// api stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SnortMLEngineModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* snort_ml_engine_ctor(Module* m)
{
    SnortMLEngineModule* mod = reinterpret_cast<SnortMLEngineModule*>(m);
    return new SnortMLEngine(mod->get_config());
}

static void snort_ml_engine_dtor(Inspector* p)
{
    assert(p);
    delete p;
}

static const InspectApi snort_ml_engine_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        PLUGIN_SO_RELOAD,
        API_OPTIONS,
        SNORT_ML_ENGINE_NAME,
        SNORT_ML_ENGINE_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__NONE,  // proto_bits;
    nullptr,  // buffers
    nullptr,  // service
    nullptr,  // pinit
    nullptr,  // pterm
    nullptr,  // tinit
    nullptr,  // tterm
    snort_ml_engine_ctor,
    snort_ml_engine_dtor,
    nullptr,  // ssn
    nullptr   // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_snort_ml_engine[] =
#endif
{
    &snort_ml_engine_api.base,
    nullptr
};

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

#include <memory.h>

TEST_CASE("SnortML tuner name", "[snort_ml_module]")
{
    SnortMLEngineConfig conf;
    conf.http_param_models = { "model" };
    SnortMLReloadTuner tuner(conf);

    REQUIRE(strcmp(tuner.name(), "SnortMLReloadTuner") == 0);
}

#endif
