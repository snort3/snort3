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
// kaizen_engine.cc author Vitalii Horbatov <vhorbato@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "kaizen_engine.h"

#include <cassert>
#include <fstream>

#ifdef HAVE_LIBML
#include <libml.h>
#endif

#include "framework/decode_data.h"
#include "log/messages.h"
#include "main/reload_tuner.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "parser/parse_conf.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL BinaryClassifier* classifier = nullptr;

static bool build_classifier(const string& model, BinaryClassifier*& dst)
{
    dst = new BinaryClassifier();

    return dst->build(model);
}

//--------------------------------------------------------------------------
// module
//--------------------------------------------------------------------------

static const Parameter kaizen_engine_params[] =
{
    { "http_param_model", Parameter::PT_STRING, nullptr, nullptr, "path to the model file" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

KaizenEngineModule::KaizenEngineModule() : Module(KZ_ENGINE_NAME, KZ_ENGINE_HELP, kaizen_engine_params) {}

bool KaizenEngineModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("http_param_model"))
        conf.http_param_model_path = v.get_string();

    return true;
}

//--------------------------------------------------------------------------
// reload tuner
//--------------------------------------------------------------------------

class KaizenReloadTuner : public snort::ReloadResourceTuner
{
public:
    explicit KaizenReloadTuner(const string& http_param_model) : http_param_model(http_param_model) {}
    ~KaizenReloadTuner() override = default;

    bool tinit() override
    {
        delete classifier;

        if (!build_classifier(http_param_model, classifier))
            ErrorMessage("Can't build the classifier model.\n");

        return false;
    }

    bool tune_packet_context() override
    { return true; }

    bool tune_idle_context() override
    { return true; }

private:
    const string& http_param_model;
};

//--------------------------------------------------------------------------
// inspector
//--------------------------------------------------------------------------

KaizenEngine::KaizenEngine(const KaizenEngineConfig& c) : config(c)
{
    http_param_model = read_model();

    if (!validate_model())
        ParseError("Can't build the classifier model %s.", config.http_param_model_path.c_str());
}

void KaizenEngine::show(const SnortConfig*) const
{ ConfigLogger::log_value("http_param_model", config.http_param_model_path.c_str()); }

string KaizenEngine::read_model()
{
    const char* hint = config.http_param_model_path.c_str();
    string path;
    size_t size = 0;

    if (!get_config_file(hint, path) || !get_file_size(path, size))
    {
        ParseError("kaizen_ml_engine: could not read model file: %s", hint);
        return {};
    }

    ifstream file(path, ios::binary);

    if (!file.is_open())
    {
        ParseError("kaizen_ml_engine: could not read model file: %s", hint);
        return {};
    }

    if (size == 0)
    {
        ParseError("kaizen_ml_engine: empty model file: %s", hint);
        return {};
    }

    string buffer(size, '\0');
    file.read(&buffer[0], streamsize(size));
    return buffer;
}

bool KaizenEngine::validate_model()
{
    BinaryClassifier* test_classifier = nullptr;
    bool res = build_classifier(http_param_model, test_classifier);
    delete test_classifier;

    return res;
}

void KaizenEngine::tinit()
{ build_classifier(http_param_model, classifier); }

void KaizenEngine::tterm()
{
    delete classifier;
    classifier = nullptr;
}

void KaizenEngine::install_reload_handler(SnortConfig* sc)
{ sc->register_reload_handler(new KaizenReloadTuner(http_param_model)); }

BinaryClassifier* KaizenEngine::get_classifier()
{ return classifier; }

//--------------------------------------------------------------------------
// api stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{ return new KaizenEngineModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* kaizen_engine_ctor(Module* m)
{
    KaizenEngineModule* mod = (KaizenEngineModule*)m;
    return new KaizenEngine(mod->get_config());
}

static void kaizen_engine_dtor(Inspector* p)
{
    assert(p);
    delete p;
}

static const InspectApi kaizen_engine_api =
{
    {
#if defined(HAVE_LIBML) || defined(REG_TEST)
        PT_INSPECTOR,
#else
        PT_MAX,
#endif
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        KZ_ENGINE_NAME,
        KZ_ENGINE_HELP,
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
    kaizen_engine_ctor,
    kaizen_engine_dtor,
    nullptr,  // ssn
    nullptr   // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_kaizen_engine[] =
#endif
{
    &kaizen_engine_api.base,
    nullptr
};
