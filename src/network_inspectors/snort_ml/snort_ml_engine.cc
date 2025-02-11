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
// snort_ml_engine.cc author Vitalii Horbatov <vhorbato@cisco.com>
//                    author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_ml_engine.h"

#include <cassert>
#include <fstream>

#ifdef HAVE_LIBML
#include <libml.h>
#endif

#include "framework/decode_data.h"
#include "helpers/directory.h"
#include "log/messages.h"
#include "main/reload_tuner.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "parser/parse_conf.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL libml::BinaryClassifierSet* classifiers = nullptr;

static bool build_classifiers(const vector<string>& models,
    libml::BinaryClassifierSet*& set)
{
    set = new libml::BinaryClassifierSet();

    return set->build(models);
}

//--------------------------------------------------------------------------
// module
//--------------------------------------------------------------------------

static const Parameter snort_ml_engine_params[] =
{
    { "http_param_model", Parameter::PT_STRING, nullptr, nullptr, "path to model file(s)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

SnortMLEngineModule::SnortMLEngineModule() : Module(SNORT_ML_ENGINE_NAME, SNORT_ML_ENGINE_HELP, snort_ml_engine_params) {}

bool SnortMLEngineModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("http_param_model"))
        conf.http_param_model_path = v.get_string();

    return true;
}

//--------------------------------------------------------------------------
// reload tuner
//--------------------------------------------------------------------------

class SnortMLReloadTuner : public snort::ReloadResourceTuner
{
public:
    explicit SnortMLReloadTuner(const vector<string>& models)
        : http_param_models(models) {}

    ~SnortMLReloadTuner() override = default;

    const char* name() const override
    { return "SnortMLReloadTuner"; }

    bool tinit() override
    {
        delete classifiers;

        if (!build_classifiers(http_param_models, classifiers))
            ErrorMessage("Could not build classifiers.\n");

        return false;
    }

    bool tune_packet_context() override
    { return true; }

    bool tune_idle_context() override
    { return true; }

private:
    const vector<string>& http_param_models;
};

//--------------------------------------------------------------------------
// inspector
//--------------------------------------------------------------------------

SnortMLEngine::SnortMLEngine(const SnortMLEngineConfig& c) : config(c)
{
    if (!read_models() || !validate_models())
        ParseError("Could not build classifiers.");
}

void SnortMLEngine::show(const SnortConfig*) const
{ ConfigLogger::log_value("http_param_model", config.http_param_model_path.c_str()); }

bool SnortMLEngine::read_models()
{
    const char* hint = config.http_param_model_path.c_str();
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

    return !http_param_models.empty();
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

    http_param_models.push_back(move(buffer));
    return true;
}

bool SnortMLEngine::validate_models()
{
    libml::BinaryClassifierSet* set = nullptr;
    bool res = build_classifiers(http_param_models, set);
    delete set;

    return res;
}

void SnortMLEngine::tinit()
{ build_classifiers(http_param_models, classifiers); }

void SnortMLEngine::tterm()
{
    delete classifiers;
    classifiers = nullptr;
}

void SnortMLEngine::install_reload_handler(SnortConfig* sc)
{ sc->register_reload_handler(new SnortMLReloadTuner(http_param_models)); }

libml::BinaryClassifierSet* SnortMLEngine::get_classifiers()
{ return classifiers; }

//--------------------------------------------------------------------------
// api stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SnortMLEngineModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* snort_ml_engine_ctor(Module* m)
{
    SnortMLEngineModule* mod = (SnortMLEngineModule*)m;
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
        API_RESERVED,
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
    const vector<string> models = { "model" };
    SnortMLReloadTuner tuner(models);

    REQUIRE(strcmp(tuner.name(), "SnortMLReloadTuner") == 0);
}

#endif
