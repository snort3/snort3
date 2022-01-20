//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// sfdaq.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfdaq.h"

#include <daq.h>

#include <algorithm>
#include <vector>

#include "log/messages.h"
#include "main/snort_config.h"

#include "sfdaq_config.h"
#include "sfdaq_instance.h"
#ifdef ENABLE_STATIC_DAQ
#include "sfdaq_static_modules.h"
#endif

using namespace snort;
using namespace std;

#ifdef DEFAULT_DAQ
#define DAQ_DEFAULT STRINGIFY_MX(DEFAULT_DAQ)
#else
#define DAQ_DEFAULT "pcap"
#endif

// common for all daq threads / instances
static DAQ_Config_h daqcfg = nullptr;
static DAQ_Mode default_daq_mode = DAQ_MODE_PASSIVE;
static string daq_module_names;
static bool loaded = false;

// specific for each thread / instance
static THREAD_LOCAL SFDAQInstance *local_instance = nullptr;

void SFDAQ::load(const SFDAQConfig* cfg)
{
    const char** dirs = new const char*[cfg->module_dirs.size() + 1];
    int i = 0;

    for (const string& module_dir : cfg->module_dirs)
        dirs[i++] = module_dir.c_str();
    dirs[i] = nullptr;

#ifdef ENABLE_STATIC_DAQ
    daq_load_static_modules(static_daq_modules);
#endif
    int err = daq_load_dynamic_modules(dirs);
    if (err)
        FatalError("Could not load dynamic DAQ modules! (%d)\n", err);

    delete[] dirs;

    loaded = true;
}

void SFDAQ::unload()
{
    daq_unload_modules();
    loaded = false;
}

void SFDAQ::print_types(ostream& ostr)
{
    DAQ_Module_h mod = daq_modules_first();

    if (mod)
        ostr << "Available DAQ modules:" << endl;
    else
        ostr << "No available DAQ modules (try adding directories with --daq-dir)." << endl;

    std::vector<DAQ_Module_h> modules;

    while (mod)
    {
        modules.push_back(mod);
        mod = daq_modules_next();
    }

    std::sort(modules.begin(), modules.end(),
        [](DAQ_Module_h a, DAQ_Module_h b)
        { return strcmp(daq_module_get_name(a), daq_module_get_name(b)) < 0; });

    for ( auto module : modules )
    {
        ostr << daq_module_get_name(module) << "(v" << daq_module_get_version(module) << "):";

        uint32_t type = daq_module_get_type(module);

        if (type & DAQ_TYPE_FILE_CAPABLE)
            ostr << " readback";

        if (type & DAQ_TYPE_INTF_CAPABLE)
            ostr << " live";

        if (type & DAQ_TYPE_INLINE_CAPABLE)
            ostr << " inline";

        if (type & DAQ_TYPE_MULTI_INSTANCE)
            ostr << " multi";

        if (!(type & DAQ_TYPE_NO_UNPRIV))
            ostr << " unpriv";

        if (type & DAQ_TYPE_WRAPPER)
            ostr << " wrapper";

        ostr << endl;

        const DAQ_VariableDesc_t *var_desc_table;
        int num_var_descs = daq_module_get_variable_descs(module, &var_desc_table);
        if (num_var_descs > 0)
        {
            ostr << " Variables:" << endl;
            for (int i = 0; i < num_var_descs; i++)
            {
                ostr << "  " << var_desc_table[i].name << " ";
                if (var_desc_table[i].flags & DAQ_VAR_DESC_REQUIRES_ARGUMENT)
                    ostr << "<arg> ";
                else if (!(var_desc_table[i].flags & DAQ_VAR_DESC_FORBIDS_ARGUMENT))
                    ostr << "[arg] ";
                ostr << "- " << var_desc_table[i].description << endl;
            }
        }
    }
}

/*
static int DAQ_ValidateModule(DAQ_Module_h module, DAQ_Mode mode)
{
    uint32_t have = daq_module_get_type(module);
    uint32_t need = 0;

    if (mode == DAQ_MODE_READ_FILE)
        need |= DAQ_TYPE_FILE_CAPABLE;

    else if (mode == DAQ_MODE_PASSIVE)
        need |= DAQ_TYPE_INTF_CAPABLE;

    else
        need |= DAQ_TYPE_INLINE_CAPABLE;

    return ((have & need) != 0);
}
*/

static bool AddDaqModuleConfig(const SFDAQModuleConfig *dmc)
{
    const char* module_name = dmc->name.c_str();
    DAQ_Module_h module = daq_find_module(module_name);
    if (!module)
    {
        ParseError("Could not find requested DAQ module: %s\n", module_name);
        return false;
    }

    DAQ_ModuleConfig_h modcfg;
    int rval;
    if ((rval = daq_module_config_new(&modcfg, module)) != DAQ_SUCCESS)
    {
        ErrorMessage("Error allocating a new DAQ module configuration object! (%d)\n", rval);
        return false;
    }

    DAQ_Mode mode;
    if (dmc->mode == SFDAQModuleConfig::SFDAQ_MODE_PASSIVE)
        mode = DAQ_MODE_PASSIVE;
    else if (dmc->mode == SFDAQModuleConfig::SFDAQ_MODE_INLINE)
        mode = DAQ_MODE_INLINE;
    else if (dmc->mode == SFDAQModuleConfig::SFDAQ_MODE_READ_FILE)
        mode = DAQ_MODE_READ_FILE;
    else
        mode = default_daq_mode;
    daq_module_config_set_mode(modcfg, mode);

    for (auto& kvp : dmc->variables)
    {
        const char* key = kvp.first.c_str();
        const char* value = kvp.second.length() ? kvp.second.c_str() : nullptr;
        if (daq_module_config_set_variable(modcfg, key, value) != DAQ_SUCCESS)
        {
            ParseError("Error setting DAQ configuration variable with key '%s' and value '%s'! (%d)",
                    key, value, rval);
            daq_module_config_destroy(modcfg);
            return false;
        }
    }

    if ((rval = daq_config_push_module_config(daqcfg, modcfg)) != DAQ_SUCCESS)
    {
        ParseError("Error pushing DAQ module configuration for '%s' onto the DAQ config! (%d)\n",
                daq_module_get_name(module), rval);
        daq_module_config_destroy(modcfg);
        return false;
    }

    if (!daq_module_names.empty())
        daq_module_names.insert(0, 1, ':');
    daq_module_names.insert(0, module_name);

    return true;
}

bool SFDAQ::init(const SFDAQConfig* cfg, unsigned total_instances)
{
    if (!loaded)
        load(cfg);

    int rval;

    if (SnortConfig::get_conf()->adaptor_inline_mode())
        default_daq_mode = DAQ_MODE_INLINE;

    else if (SnortConfig::get_conf()->read_mode())
        default_daq_mode = DAQ_MODE_READ_FILE;

    else
        default_daq_mode = DAQ_MODE_PASSIVE;

    if ((rval = daq_config_new(&daqcfg)) != DAQ_SUCCESS)
    {
        ErrorMessage("Error allocating a new DAQ configuration object! (%d)\n", rval);
        return false;
    }

    daq_config_set_msg_pool_size(daqcfg, cfg->get_batch_size() * 4);
    daq_config_set_snaplen(daqcfg, cfg->get_mru_size());
    daq_config_set_timeout(daqcfg, cfg->timeout);
    if (total_instances > 1)
        daq_config_set_total_instances(daqcfg, total_instances);

    /* If no modules were specified, try to automatically configure with the default. */
    if (cfg->module_configs.empty())
    {
        SFDAQModuleConfig dmc;
        dmc.name = DAQ_DEFAULT;
        if (!AddDaqModuleConfig(&dmc))
        {
            daq_config_destroy(daqcfg);
            daqcfg = nullptr;
            return false;
        }
    }
    /* Otherwise, if the module stack doesn't have a terminal module at the bottom, default
        to a hardcoded base of the PCAP DAQ module in read-file mode.  This is a convenience
        provided to emulate the previous dump/regtest DAQ module behavior. */
    else
    {
        const char* module_name = cfg->module_configs[0]->name.c_str();
        DAQ_Module_h module = daq_find_module(module_name);
        if (module && (daq_module_get_type(module) & DAQ_TYPE_WRAPPER))
        {
            SFDAQModuleConfig dmc;
            dmc.name = "pcap";
            dmc.mode = SFDAQModuleConfig::SFDAQ_MODE_READ_FILE;
            if (!AddDaqModuleConfig(&dmc))
            {
                daq_config_destroy(daqcfg);
                daqcfg = nullptr;
                return false;
            }
        }
    }

    for (SFDAQModuleConfig* dmc : cfg->module_configs)
    {
        if (!AddDaqModuleConfig(dmc))
        {
            daq_config_destroy(daqcfg);
            daqcfg = nullptr;
            return false;
        }
    }

/*
    if (!DAQ_ValidateModule(daq_mode))
        FatalError("%s DAQ does not support %s.\n", type, daq_mode_string(daq_mode));

*/
    LogMessage("%s DAQ configured to %s.\n", daq_module_names.c_str(), daq_mode_string(default_daq_mode));

    return true;
}

void SFDAQ::term()
{
    if (daqcfg)
    {
        daq_config_destroy(daqcfg);
        daqcfg = nullptr;
    }
#ifndef REG_TEST
    if (loaded)
        unload();
#endif
}

const char* SFDAQ::verdict_to_string(DAQ_Verdict verdict)
{
    return daq_verdict_string(verdict);
}

bool SFDAQ::forwarding_packet(const DAQ_PktHdr_t* h)
{
    // DAQ mode is inline and the packet will be forwarded?
    return (default_daq_mode == DAQ_MODE_INLINE && !(h->flags & DAQ_PKT_FLAG_NOT_FORWARDING));
}

bool SFDAQ::can_run_unprivileged()
{
    // Iterate over the configured modules to see if any of them don't support unprivileged operation
    DAQ_ModuleConfig_h modcfg = daq_config_top_module_config(daqcfg);
    while (modcfg)
    {
        DAQ_Module_h module = daq_module_config_get_module(modcfg);
        if (daq_module_get_type(module) & DAQ_TYPE_NO_UNPRIV)
            return false;
        modcfg = daq_config_next_module_config(daqcfg);
    }
    return true;
}

bool SFDAQ::init_instance(SFDAQInstance* instance, const string& bpf_string)
{
    return instance->init(daqcfg, bpf_string);
}

/*
 * SFDAQ local instance wrappers (to be removed)
 */

void SFDAQ::set_local_instance(SFDAQInstance* sdi)
{
    local_instance = sdi;
}

SFDAQInstance* SFDAQ::get_local_instance()
{
    return local_instance;
}

const char* SFDAQ::get_input_spec()
{
    return local_instance->get_input_spec();
}

int SFDAQ::get_base_protocol()
{
    return local_instance->get_base_protocol();
}

bool SFDAQ::can_inject()
{
    return local_instance && local_instance->can_inject();
}

bool SFDAQ::can_inject_raw()
{
    return local_instance && local_instance->can_inject_raw();
}

bool SFDAQ::can_replace()
{
    return local_instance && local_instance->can_replace();
}

bool SFDAQ::get_tunnel_bypass(uint16_t proto)
{
    return local_instance && local_instance->get_tunnel_bypass(proto);
}

int SFDAQ::inject(DAQ_Msg_h msg, int rev, const uint8_t* buf, uint32_t len)
{
    return local_instance->inject(msg, rev, buf, len);
}

const DAQ_Stats_t* SFDAQ::get_stats()
{
    return local_instance->get_stats();
}

const char* SFDAQ::get_input_spec(const SFDAQConfig* cfg, unsigned instance_id)
{
    if (cfg->inputs.empty())
        return nullptr;

    if (instance_id > 0 && instance_id < cfg->inputs.size())
        return cfg->inputs[instance_id].c_str();

    return cfg->inputs[0].c_str();
}

const char* SFDAQ::default_type()
{
    return DAQ_DEFAULT;
}

