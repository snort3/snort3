//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// sfdaq_module.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfdaq_module.h"

#include <cassert>

#include "log/messages.h"
#include "main/snort_config.h"

#include "sfdaq_config.h"

#define sfdaq_help "configure packet acquisition interface"

static const Parameter string_list_param[] =
{
    { "str", Parameter::PT_STRING, nullptr, nullptr, "string parameter" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter instance_params[] =
{
    { "id", Parameter::PT_INT, "0:", nullptr, "instance ID (required)" },
    { "input_spec", Parameter::PT_STRING, nullptr, nullptr, "input specification" },
    { "variables", Parameter::PT_LIST, string_list_param, nullptr, "DAQ variables" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "module_dirs", Parameter::PT_LIST, string_list_param, nullptr, "directories to search for DAQ modules" },
    { "input_spec", Parameter::PT_STRING, nullptr, nullptr, "input specification" },
    { "module", Parameter::PT_STRING, nullptr, nullptr, "DAQ module to use" },
    { "variables", Parameter::PT_LIST, string_list_param, nullptr, "DAQ variables" },
    { "instances", Parameter::PT_LIST, instance_params, nullptr, "DAQ instance overrides" },
    { "snaplen", Parameter::PT_INT, "0:65535", nullptr, "set snap length (same as -s)" },
    { "no_promisc", Parameter::PT_BOOL, nullptr, "false", "whether to put DAQ device into promiscuous mode" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

SFDAQModule::SFDAQModule() : Module("daq", sfdaq_help, s_params)
{
    config = nullptr;
    instance_config = nullptr;
}

SFDAQModule::~SFDAQModule()
{
}

bool SFDAQModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if (!strcmp(fqn, "daq"))
        config = new SFDAQConfig();

    else if (!strcmp(fqn, "daq.instances"))
    {
        if (idx == 0)
            return true;

        assert(!instance_config);
        instance_config = new SFDAQInstanceConfig();

        instance_id = -1;
    }
    return true;
}

bool SFDAQModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    if (!strcmp(fqn, "daq.module_dirs"))
    {
        config->add_module_dir(v.get_string());
    }
    else if (!strcmp(fqn, "daq.module"))
    {
        config->set_module_name(v.get_string());
    }
    else if (!strcmp(fqn, "daq.input_spec"))
    {
        config->set_input_spec(v.get_string());
    }
    else if (!strcmp(fqn, "daq.variables"))
    {
        config->set_variable(v.get_string());
    }
    else if (!strcmp(fqn, "daq.snaplen"))
    {
        config->set_mru_size(v.get_long());
    }
    else if (!strcmp(fqn, "daq.no_promisc"))
    {
        v.update_mask(sc->run_flags, RUN_FLAG__NO_PROMISCUOUS);
    }
    else if (!strcmp(fqn, "daq.instances.id"))
    {
        instance_id = v.get_long();
    }
    else if (!strcmp(fqn, "daq.instances.input_spec"))
    {
        instance_config->set_input_spec(v.get_string());
    }
    else if (!strcmp(fqn, "daq.instances.variables"))
    {
        instance_config->set_variable(v.get_string());
    }

    return true;
}

bool SFDAQModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if (!strcmp(fqn, "daq.instances"))
    {
        if (idx == 0)
            return true;

        if (instance_id < 0 or config->instances[instance_id])
        {
            ParseError("%s - duplicate or no DAQ instance ID specified", fqn);
            delete instance_config;
            instance_config = nullptr;
            return false;
        }
        config->instances[instance_id] = instance_config;
        instance_config = nullptr;
    }
    else if (!strcmp(fqn, "daq"))
    {
        if ( sc->daq_config )
            delete sc->daq_config;

        sc->daq_config = config;
        config = nullptr;
    }

    return true;
}

const PegInfo* SFDAQModule::get_pegs() const
{
    return daq_names;
}

PegCount* SFDAQModule::get_counts() const
{
    static THREAD_LOCAL DAQStats ds;

    get_daq_stats(ds);
    return (PegCount*) &ds;
}

