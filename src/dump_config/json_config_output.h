//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
// json_config_output.h author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifndef JSON_CONFIG_OUTPUT_H
#define JSON_CONFIG_OUTPUT_H

#include <fstream>

#include "config_output.h"
#include "helpers/json_stream.h"

class BaseConfigNode;

class JsonAllConfigOutput : public ConfigOutput
{
public:
    JsonAllConfigOutput(const char *file_name = nullptr);
    ~JsonAllConfigOutput() override;

private:
    void dump(const ConfigData&) override;

private:
    std::fstream *file;
    snort::JsonStream *json;
};

class JsonTopConfigOutput : public ConfigOutput
{
public:
    JsonTopConfigOutput() : ConfigOutput(), json(std::cout) {}

private:
    void dump(const ConfigData&) override;

private:
    snort::JsonStream json;
};

#endif // JSON_CONFIG_OUTPUT_H
