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
// kaizen_engine.h author Vitalii Horbatov <vhorbato@cisco.com>

#ifndef KAIZEN_ENGINE_H
#define KAIZEN_ENGINE_H

#include "framework/module.h"
#include "framework/inspector.h"


#define KZ_ENGINE_NAME "kaizen_ml_engine"
#define KZ_ENGINE_HELP "configure machine learning engine settings"

class BinaryClassifier;
struct KaizenEngineConfig
{
    std::string http_param_model_path;
};

class KaizenEngineModule : public snort::Module
{
public:
    KaizenEngineModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

    const KaizenEngineConfig& get_config()
    { return conf; }

private:
    KaizenEngineConfig conf;
};


class KaizenEngine : public snort::Inspector
{
public:
    KaizenEngine(const KaizenEngineConfig&);

    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet*) override {}

    void tinit() override;
    void tterm() override;

    void install_reload_handler(snort::SnortConfig*) override;

    static BinaryClassifier* get_classifier();

private:
    std::string read_model();
    bool validate_model();

    KaizenEngineConfig config;
    std::string http_param_model;
};


// Mock Classifier for tests if LibML absents.
// However, when REG_TEST is undefined, the entire code below won't be executed.
// Check the plugin type provided in kaizen_engine_api in the cc file
#ifndef HAVE_LIBML
class BinaryClassifier
{
public:
    bool build(const std::string& model)
    {
        pattern = model;
        return pattern != "error";
    }

    bool run(const char* ptr, size_t len, float& threshold)
    {
        std::string data(ptr, len);
        threshold = std::string::npos == data.find(pattern) ? 0.0f : 1.0f;
        return pattern != "fail";
    }

private:
    std::string pattern;
};
#endif

#endif
