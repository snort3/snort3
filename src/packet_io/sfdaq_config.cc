//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

static const unsigned DEFAULT_PKT_TIMEOUT = 1000;    // ms, worst daq resolution is 1 sec

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
 * SFDAQConfigInstance
 */

SFDAQInstanceConfig::SFDAQInstanceConfig(const SFDAQInstanceConfig& other)
{
    input_spec = other.input_spec;
    variables = other.variables;
}

void SFDAQInstanceConfig::set_input_spec(const char* input_spec_str)
{
    if (input_spec_str)
        input_spec = input_spec_str;
    else
        input_spec.clear();
}

void SFDAQInstanceConfig::set_variable(const char* varkvp)
{
    variables.push_back(parse_variable(varkvp));
}

/*
 * SFDAQConfig
 */

SFDAQConfig::SFDAQConfig()
{
    mru_size = -1;
    timeout = DEFAULT_PKT_TIMEOUT;
}

SFDAQConfig::~SFDAQConfig()
{
    for (auto it : instances)
        delete it.second;
}

void SFDAQConfig::add_module_dir(const char* module_dir)
{
    if (module_dir)
        module_dirs.push_back(module_dir);
}

void SFDAQConfig::set_input_spec(const char* input_spec_str, int instance_id)
{
    if (instance_id >= 0)
    {
        SFDAQInstanceConfig* ic;

        auto it = instances.find(instance_id);
        if (it == instances.end())
        {
            ic = new SFDAQInstanceConfig;
            instances[instance_id] = ic;
        }
        else
            ic = it->second;

        ic->set_input_spec(input_spec_str);
    }
    else
    {
        if (input_spec_str)
            input_spec = input_spec_str;
        else
            input_spec.clear();
    }
}

void SFDAQConfig::set_module_name(const char* module_name_str)
{
    if (module_name_str)
        module_name = module_name_str;
}

void SFDAQConfig::set_mru_size(int mru_size_value)
{
    mru_size = mru_size_value;
}

void SFDAQConfig::set_variable(const char* varkvp, int instance_id)
{
    if (instance_id >= 0)
    {
        SFDAQInstanceConfig* ic;

        auto it = instances.find(instance_id);
        if (it == instances.end())
        {
            ic = new SFDAQInstanceConfig;
            instances[instance_id] = ic;
        }
        else
            ic = it->second;

        ic->set_variable(varkvp);
    }
    else
        variables.push_back(parse_variable(varkvp));
}

void SFDAQConfig::overlay(const SFDAQConfig* other)
{
    if (!other->module_dirs.empty())
        module_dirs = other->module_dirs;

    if (!other->module_name.empty())
        module_name = other->module_name;

    if (!other->input_spec.empty())
        input_spec = other->input_spec;

    if (!other->variables.empty())
        variables = other->variables;

    if (other->mru_size != -1)
        mru_size = other->mru_size;

    for (auto oit = other->instances.begin(); oit != other->instances.end(); oit++)
    {
        SFDAQInstanceConfig* oic = oit->second;
        SFDAQInstanceConfig* ic;
        auto it = instances.find(oit->first);
        if (it != instances.end())
        {
            ic = it->second;
            if (!oic->input_spec.empty())
                ic->input_spec = oic->input_spec;
            if (!oic->variables.empty())
                ic->variables = oic->variables;
        }
        else
        {
            ic = new SFDAQInstanceConfig(*oic);
            instances[oit->first] = ic;
        }
    }
}
