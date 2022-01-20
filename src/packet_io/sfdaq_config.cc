//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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

// sfdaq_config.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfdaq_config.h"

using namespace std;

static pair<string, string> parse_variable(const char* varkvp)
{
    string key = varkvp;
    string value;
    size_t pos;

    if ((pos = key.find_first_of('=')) != std::string::npos)
    {
        value = key.substr(pos + 1);
        key.erase(pos);
    }

    return make_pair(key, value);
}

/*
 * SFDAQModuleConfig
 */

SFDAQModuleConfig::SFDAQModuleConfig(const SFDAQModuleConfig& other)
{
    name = other.name;
    mode = other.mode;
    variables = other.variables;
}

void SFDAQModuleConfig::set_variable(const char* varkvp)
{
    if (varkvp)
        variables.emplace_back(parse_variable(varkvp));
}


/*
 * SFDAQConfig
 */

SFDAQConfig::SFDAQConfig()
{
    batch_size = BATCH_SIZE_UNSET;
    mru_size = SNAPLEN_UNSET;
    timeout = TIMEOUT_DEFAULT;
}

SFDAQConfig::~SFDAQConfig()
{
    for (auto it : module_configs)
        delete it;
}

void SFDAQConfig::add_input(const char* input)
{
    if (input)
        inputs.emplace_back(input);
}

SFDAQModuleConfig* SFDAQConfig::add_module_config(const char* module_name)
{
    SFDAQModuleConfig* modcfg = new SFDAQModuleConfig();
    modcfg->name = module_name;
    module_configs.emplace_back(modcfg);
    return modcfg;
}

void SFDAQConfig::add_module_dir(const char* module_dir)
{
    if (module_dir)
        module_dirs.emplace_back(module_dir);
}

void SFDAQConfig::set_batch_size(uint32_t batch_size_value)
{
    batch_size = batch_size_value;
}

void SFDAQConfig::set_mru_size(int mru_size_value)
{
    mru_size = mru_size_value;
}

void SFDAQConfig::overlay(const SFDAQConfig* other)
{
    if (!other->module_dirs.empty())
        module_dirs = other->module_dirs;

    if (!other->module_configs.empty())
    {
        for (SFDAQModuleConfig *dmc : module_configs)
            delete dmc;
        module_configs.clear();
        for (SFDAQModuleConfig *dmc : other->module_configs)
            module_configs.emplace_back(new SFDAQModuleConfig(*dmc));
    }

    if (!other->inputs.empty())
        inputs = other->inputs;

    if (other->batch_size != BATCH_SIZE_UNSET)
        batch_size = other->batch_size;
    if (other->mru_size != SNAPLEN_UNSET)
        mru_size = other->mru_size;
    timeout = other->timeout;
}
