//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
// Copyright (C) 2014-2016 Titan IC Systems Ltd. All rights reserved.
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

#include "sfdaq.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <mutex>
#include <ostream>

extern "C" {
#include <daq.h>
#include <sfbpf_dlt.h>
}

#include "sfdaq_config.h"
#include "main/snort_config.h"
#include "parser/parser.h"
#include "utils/util.h"

using namespace std;

#ifdef DEFAULT_DAQ
#define XSTR(s) STR(s)
#define STR(s) #s
#define DAQ_DEFAULT XSTR(DEFAULT_DAQ)
#else
#define DAQ_DEFAULT "pcap"
#endif

static const int DEFAULT_PKT_SNAPLEN = 1514;

// common for all daq threads / instances
static const DAQ_Module_t* daq_mod = nullptr;
static DAQ_Mode daq_mode = DAQ_MODE_PASSIVE;
static uint32_t snap = DEFAULT_PKT_SNAPLEN;
static bool loaded = false;

// specific for each thread / instance
static THREAD_LOCAL SFDAQInstance *local_instance = nullptr;

#include "tics/tics.h"

/*
 * SFDAQ
 */

void SFDAQ::load(const SnortConfig* sc)
{
    const char** dirs = new const char*[sc->daq_config->module_dirs.size() + 1];
    int i = 0;

    for (string& module_dir : sc->daq_config->module_dirs)
        dirs[i++] = module_dir.c_str();
    dirs[i] = nullptr;

    int err = daq_load_modules(dirs);

    if (err)
        FatalError("Can't load DAQ modules = %d\n", err);

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
    DAQ_Module_Info_t* list = NULL;
    int i, nMods = daq_get_module_list(&list);

    if (nMods)
        ostr << "Available DAQ modules:" << endl;
    else
        ostr << "No available DAQ modules (try adding directories with --daq-dir)." << endl;

    for (i = 0; i < nMods; i++)
    {
        ostr << list[i].name << "(v" << list[i].version << "):";

        if (list[i].type & DAQ_TYPE_FILE_CAPABLE)
            ostr << " readback";

        if (list[i].type & DAQ_TYPE_INTF_CAPABLE)
            ostr << " live";

        if (list[i].type & DAQ_TYPE_INLINE_CAPABLE)
            ostr << " inline";

        if (list[i].type & DAQ_TYPE_MULTI_INSTANCE)
            ostr << " multi";

        if (!(list[i].type & DAQ_TYPE_NO_UNPRIV))
            ostr << " unpriv";

        ostr << endl;
    }
    daq_free_module_list(list, nMods);
}

static int DAQ_ValidateModule(DAQ_Mode mode)
{
    uint32_t have = daq_get_type(daq_mod);
    uint32_t need = 0;

    if (mode == DAQ_MODE_READ_FILE)
        need |= DAQ_TYPE_FILE_CAPABLE;

    else if (mode == DAQ_MODE_PASSIVE)
        need |= DAQ_TYPE_INTF_CAPABLE;

    else
        need |= DAQ_TYPE_INLINE_CAPABLE;

    return ((have & need) != 0);
}

void SFDAQ::init(const SnortConfig* sc)
{
    if (!loaded)
        load(sc);

    const char* type = DAQ_DEFAULT;

    if (sc->daq_config->module_name.size())
        type = sc->daq_config->module_name.c_str();

    daq_mod = daq_find_module(type);

    if (!daq_mod)
        FatalError("Can't find %s DAQ\n", type);

    snap = (sc->daq_config->mru_size > 0) ? sc->daq_config->mru_size : DEFAULT_PKT_SNAPLEN;

    if (SnortConfig::adaptor_inline_mode())
        daq_mode = DAQ_MODE_INLINE;
    else if (SnortConfig::read_mode())
        daq_mode = DAQ_MODE_READ_FILE;
    else
        daq_mode = DAQ_MODE_PASSIVE;

    if (!DAQ_ValidateModule(daq_mode))
        FatalError("%s DAQ does not support %s.\n", type, daq_mode_string(daq_mode));

    LogMessage("%s DAQ configured to %s.\n", type, daq_mode_string(daq_mode));
}

void SFDAQ::term()
{
    if (loaded)
        unload();
    daq_mod = nullptr;
}

bool SFDAQ::forwarding_packet(const DAQ_PktHdr_t* h)
{
    // DAQ mode is inline and the packet will be forwarded?
    return (daq_mode == DAQ_MODE_INLINE && !(h->flags & DAQ_PKT_FLAG_NOT_FORWARDING));
}

const char* SFDAQ::get_type()
{
    return daq_mod ? daq_get_name(daq_mod) : "error";
}

// Snort has its own snap applied to packets it acquires via the DAQ.  This
// should not be confused with the snap that was used to capture a pcap which
// may be different.
uint32_t SFDAQ::get_snap_len()
{
    return snap;
}

bool SFDAQ::unprivileged()
{
    return !(daq_get_type(daq_mod) & DAQ_TYPE_NO_UNPRIV);
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

const char* SFDAQ::get_interface_spec()
{
    return local_instance->get_interface_spec();
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
    // FIXIT-H X can_replace() is beyond broken.
    if (!local_instance)
        return true;
    return local_instance->can_replace();
}

int SFDAQ::inject(const DAQ_PktHdr_t* hdr, int rev, const uint8_t* buf, uint32_t len)
{
    return local_instance->inject(hdr, rev, buf, len);
}

bool SFDAQ::break_loop(int error)
{
    return local_instance->break_loop(error);
}

const DAQ_Stats_t* SFDAQ::get_stats()
{
    return local_instance->get_stats();
}

const char* SFDAQ::get_input_spec(const SnortConfig* sc, unsigned instance_id)
{
    auto it = sc->daq_config->instances.find(instance_id);
    if (it != sc->daq_config->instances.end() && it->second->input_spec.size())
        return it->second->input_spec.c_str();

    if (sc->daq_config->input_spec.size())
        return sc->daq_config->input_spec.c_str();

    return nullptr;
}

const char* SFDAQ::default_type()
{
    return DAQ_DEFAULT;
}

/*
 * SFDAQInstance
 */

SFDAQInstance::SFDAQInstance(const char* intf)
{
    if (intf)
        interface_spec = intf;
    daq_hand = nullptr;
    daq_dlt = -1;
    s_error = DAQ_SUCCESS;
    memset(&daq_stats, 0, sizeof(daq_stats));
}

SFDAQInstance::~SFDAQInstance()
{
    if (daq_hand)
        daq_shutdown(daq_mod, daq_hand);
}

static bool DAQ_ValidateInstance(void* daq_hand)
{
    uint32_t caps = daq_get_capabilities(daq_mod, daq_hand);

    if (!SnortConfig::adaptor_inline_mode())
        return true;

    if (!(caps & DAQ_CAPA_BLOCK))
        ParseWarning(WARN_DAQ, "inline mode configured but DAQ can't block packets.\n");

    return true;
}

bool SFDAQInstance::configure(const SnortConfig* sc)
{
    DAQ_Config_t cfg;
    const char* type = daq_get_name(daq_mod);
    char buf[256] = "";
    int err;

    memset(&cfg, 0, sizeof(cfg));

    cfg.name = (char*) interface_spec.c_str();
    cfg.snaplen = snap;
    cfg.timeout = sc->daq_config->timeout;
    cfg.mode = daq_mode;
    cfg.extra = nullptr;
    cfg.flags = 0;

#ifndef TICS_USE_LOAD_BALANCE
    if (strcasecmp(type, "tics_daq") == 0)
    {
        fprintf(stdout, "daq [%s] is selected, in order to use tics-daq, "
                        "the macro TICS_USE_LOAD_BALANCE should be enabled\n", type);
        exit (-1);
    }
#else /* !TICS_USE_LOAD_BALANCE */
    if (strcasecmp(type, "tics_daq") == 0)
    {
        cfg.name = (char *) sc->dpdk_eal_cmd_cstr;
        char * tmp_value = (char *)malloc(sizeof(char)*128);
        if (!tmp_value)
        {
            fprintf(stdout, "tmp_value allocation error in %s\n", __FUNCTION__);
            exit(-1);
        }
        else
        {
            sprintf(tmp_value, "%d%c", enabled_rxp_queue_cnt, '\0');
            daq_config_set_value(&cfg, "rxp_queue_cnt", tmp_value);
            sprintf(tmp_value, "%d%c", sc->dpdk_data_port_cnt, '\0');
            daq_config_set_value(&cfg, "data_port_cnt", tmp_value);
            #ifdef TICS_USE_RXP_MATCH
                sprintf(tmp_value, "%d%c", 1, '\0');
            #else /* TICS_USE_RXP_MATCH */
                sprintf(tmp_value, "%d%c", 0, '\0');
            #endif /* TICS_USE_RXP_MATCH */
            daq_config_set_value(&cfg, "dpdk_init_by_snort", tmp_value);
        }
    }
    else
    {
        fprintf(stdout, "daq [%s] is selected, "
                        "but the macro TICS_USE_LOAD_BALANCE is enabled, "
                        "in order to use tics-load-balance, "
                        "daq [tics_daq] should be used\n", type);
        exit (-1);
    }
#endif /* TICS_USE_LOAD_BALANCE */

    for (auto& kvp : sc->daq_config->variables)
    {
        daq_config_set_value(&cfg, kvp.first.c_str(),
                kvp.second.length() ? kvp.second.c_str() : NULL);
    }

    auto it = sc->daq_config->instances.find(get_instance_id());
    if (it != sc->daq_config->instances.end())
    {
        for (auto& kvp : it->second->variables)
        {
            daq_config_set_value(&cfg, kvp.first.c_str(),
                    kvp.second.length() ? kvp.second.c_str() : NULL);
        }
    }

    if (!SnortConfig::read_mode())
    {
        if (!(sc->run_flags & RUN_FLAG__NO_PROMISCUOUS))
            cfg.flags |= DAQ_CFG_PROMISC;
    }

    // ideally this would be configurable ...
    if (!strcasecmp(type, "dump"))
        cfg.extra = (char*)daq_find_module("pcap");

    err = daq_initialize(daq_mod, &cfg, &daq_hand, buf, sizeof(buf));
    if (err)
    {
        ErrorMessage("Can't initialize DAQ %s (%d) - %s\n", type, err, buf);
        return false;
    }
    daq_config_clear_values(&cfg);

    if (!DAQ_ValidateInstance(daq_hand))
        FatalError("DAQ configuration incompatible with intended operation.\n");

    set_filter(sc->bpf_filter.c_str());

    return true;
}

void SFDAQInstance::abort()
{
    if (was_started())
        stop();

    //DAQ_Delete();
    //DAQ_Term();  FIXIT-L this must be called from main thread on abort
}

const char* SFDAQInstance::get_interface_spec()
{
    return interface_spec.c_str();
}

// That distinction does not hold with datalink types.  Snort must use whatever
// datalink type the DAQ coughs up as its base protocol decoder.  For pcaps,
// the datalink type in the file must be used - which may not be known until
// start.  The value is cached here since it used for packet operations like
// logging and is needed at shutdown.  This avoids sequencing issues.
int SFDAQInstance::get_base_protocol()
{
    return daq_dlt;
}

bool SFDAQInstance::can_inject()
{
    return (daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_INJECT) != 0;
}

bool SFDAQInstance::can_inject_raw()
{
    return (daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_INJECT_RAW) != 0;
}

bool SFDAQInstance::can_replace()
{
    return (daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_REPLACE) != 0;
}

bool SFDAQInstance::can_start_unprivileged()
{
    return (daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_UNPRIV_START) != 0;
}

bool SFDAQInstance::can_whitelist()
{
    return (daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_WHITELIST) != 0;
}

bool SFDAQInstance::set_filter(const char* bpf)
{
    int err = 0;
    static std::mutex bpf_gate;

    // doesn't look like the bpf flex scanner is reentrant
    bpf_gate.lock();

    if (bpf and *bpf)
        err = daq_set_filter(daq_mod, daq_hand, bpf);

    bpf_gate.unlock();

    if (err)
        FatalError("Can't set DAQ BPF filter to '%s' (%s)\n",
            bpf, daq_get_error(daq_mod, daq_hand));

    return (err == DAQ_SUCCESS);
}

bool SFDAQInstance::start()
{
    int err = daq_start(daq_mod, daq_hand);

    if (err)
        ErrorMessage("Can't start DAQ (%d) - %s\n", err, daq_get_error(daq_mod, daq_hand));
    else
        daq_dlt = daq_get_datalink_type(daq_mod, daq_hand);

    return (err == DAQ_SUCCESS);
}

bool SFDAQInstance::was_started()
{
    DAQ_State s;

    if (!daq_hand)
        return false;

    s = daq_check_status(daq_mod, daq_hand);

    return (DAQ_STATE_STARTED == s);
}

bool SFDAQInstance::stop()
{
    int err = daq_stop(daq_mod, daq_hand);

    if (err)
        LogMessage("Can't stop DAQ (%d) - %s\n", err, daq_get_error(daq_mod, daq_hand));

    return (err == DAQ_SUCCESS);
}

void SFDAQInstance::set_metacallback(DAQ_Meta_Func_t meta_callback)
{
    daq_meta_callback = meta_callback;
}

int SFDAQInstance::acquire(int max, DAQ_Analysis_Func_t callback)
{
    int err = daq_acquire_with_meta(daq_mod, daq_hand, max, callback, daq_meta_callback, NULL);

    if (err && err != DAQ_READFILE_EOF)
        LogMessage("Can't acquire (%d) - %s\n", err, daq_get_error(daq_mod, daq_hand));

    if (s_error != DAQ_SUCCESS)
    {
        err = s_error;
        s_error = DAQ_SUCCESS;
    }
    return err;
}

int SFDAQInstance::inject(const DAQ_PktHdr_t* h, int rev, const uint8_t* buf, uint32_t len)
{
    int err = daq_inject(daq_mod, daq_hand, (DAQ_PktHdr_t*)h, buf, len, rev);
#ifdef DEBUG_MSGS
    if (err)
        LogMessage("Can't inject (%d) - %s\n", err, daq_get_error(daq_mod, daq_hand));
#endif
    return err;
}

bool SFDAQInstance::break_loop(int error)
{
    s_error = error;
    return (daq_breakloop(daq_mod, daq_hand) == DAQ_SUCCESS);
}

// returns statically allocated stats - don't free
const DAQ_Stats_t* SFDAQInstance::get_stats()
{
    if (daq_hand)
    {
        int err = daq_get_stats(daq_mod, daq_hand, &daq_stats);

        if (err)
            LogMessage("Can't get DAQ stats (%d) - %s\n", err, daq_get_error(daq_mod, daq_hand));

        // Some DAQs don't provide hw numbers, so we default HW RX to the SW equivalent
        // (this means outstanding packets = 0)
        if (!daq_stats.hw_packets_received)
            daq_stats.hw_packets_received = daq_stats.packets_received + daq_stats.packets_filtered;
    }

    return &daq_stats;
}

int SFDAQInstance::modify_flow_opaque(const DAQ_PktHdr_t* hdr, uint32_t opaque)
{
    DAQ_ModFlow_t mod;

#ifdef DAQ_MODFLOW_TYPE_OPAQUE
    mod.type = DAQ_MODFLOW_TYPE_OPAQUE;
    mod.length = sizeof(opaque);
    mod.value = &opaque;
#else
    mod.opaque = opaque;
#endif

    return daq_modify_flow(daq_mod, daq_hand, hdr, &mod);
}
