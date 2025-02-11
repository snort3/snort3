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
// snort_ml_engine.h author Vitalii Horbatov <vhorbato@cisco.com>
//                   author Brandon Stultz <brastult@cisco.com>

#ifndef SNORT_ML_ENGINE_H
#define SNORT_ML_ENGINE_H

#include "framework/module.h"
#include "framework/inspector.h"

#define SNORT_ML_ENGINE_NAME "snort_ml_engine"
#define SNORT_ML_ENGINE_HELP "configure machine learning engine settings"

namespace libml
{
    class BinaryClassifierSet;
}

struct SnortMLEngineConfig
{
    std::string http_param_model_path;
};

class SnortMLEngineModule : public snort::Module
{
public:
    SnortMLEngineModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

    const SnortMLEngineConfig& get_config()
    { return conf; }

private:
    SnortMLEngineConfig conf;
};

class SnortMLEngine : public snort::Inspector
{
public:
    SnortMLEngine(const SnortMLEngineConfig&);

    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet*) override {}

    void tinit() override;
    void tterm() override;

    void install_reload_handler(snort::SnortConfig*) override;

    static libml::BinaryClassifierSet* get_classifiers();

private:
    bool read_models();
    bool read_model(const std::string&);

    bool validate_models();

    SnortMLEngineConfig config;
    std::vector<std::string> http_param_models;
};

// Mock BinaryClassifierSet for tests if LibML is absent.
// The code below won't be executed if REG_TEST is undefined.
// Check the plugin type provided in the snort_ml_engine.cc file.
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

#endif
