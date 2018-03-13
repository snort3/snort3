//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

extern "C" {
#include <daq.h>
#include <sfbpf_dlt.h>
}

#include <mutex>

#include "log/messages.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "protocols/vlan.h"

#include "sfdaq_config.h"

using namespace snort;
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
static std::mutex bpf_gate;

// specific for each thread / instance
static THREAD_LOCAL SFDAQInstance *local_instance = nullptr;

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
    DAQ_Module_Info_t* list = nullptr;
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

    if (!sc->daq_config->module_name.empty())
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

const char* SFDAQ::verdict_to_string(DAQ_Verdict verdict)
{
    return daq_verdict_string(verdict);
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
    return local_instance && local_instance->can_replace();
}

bool SFDAQ::can_retry()
{
    return local_instance && local_instance->can_retry();
}

bool SFDAQ::get_tunnel_bypass(uint8_t proto)
{
    return local_instance && local_instance->get_tunnel_bypass(proto);
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
    if (it != sc->daq_config->instances.end() && !it->second->input_spec.empty())
        return it->second->input_spec.c_str();

    if (!sc->daq_config->input_spec.empty())
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
    daq_tunnel_mask = 0;
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

    cfg.name = const_cast<char*>(interface_spec.c_str());
    cfg.snaplen = snap;
    cfg.timeout = sc->daq_config->timeout;
    cfg.mode = daq_mode;
    cfg.extra = nullptr;
    cfg.flags = 0;

    for (auto& kvp : sc->daq_config->variables)
    {
        daq_config_set_value(&cfg, kvp.first.c_str(),
                kvp.second.length() ? kvp.second.c_str() : nullptr);
    }

    auto it = sc->daq_config->instances.find(get_instance_id());
    if (it != sc->daq_config->instances.end())
    {
        for (auto& kvp : it->second->variables)
        {
            daq_config_set_value(&cfg, kvp.first.c_str(),
                    kvp.second.length() ? kvp.second.c_str() : nullptr);
        }
    }

    if (!SnortConfig::read_mode())
    {
        if (!(sc->run_flags & RUN_FLAG__NO_PROMISCUOUS))
            cfg.flags |= DAQ_CFG_PROMISC;
    }

    // FIXIT-M - This is sort of an abomination and would ideally be configurable ...
    if (!strcasecmp(type, "dump") or !strcasecmp(type, "regtest"))
        cfg.extra = reinterpret_cast<char*>(const_cast<DAQ_Module_t*>(daq_find_module("pcap")));

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

void SFDAQInstance::reload()
{
    void* old_config = nullptr;
    void* new_config = nullptr;
    if (daq_mod && daq_hand)
    {
        if ( ( daq_hup_prep(daq_mod, daq_hand, &new_config) == DAQ_SUCCESS ) and
            ( daq_hup_apply(daq_mod, daq_hand, new_config, &old_config) == DAQ_SUCCESS ) )
        {
            daq_hup_post(daq_mod, daq_hand, old_config);
        }
    }
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

bool SFDAQInstance::can_retry()
{
    return (daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_RETRY) != 0;
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

    // The BPF can be compiled either during daq_set_filter() or daq_start(),
    // so protect the thread-unsafe BPF scanner/compiler in both places.

    if (bpf and *bpf)
    {
        std::lock_guard<std::mutex> lock(bpf_gate);
        err = daq_set_filter(daq_mod, daq_hand, bpf);
    }

    if (err)
        FatalError("Can't set DAQ BPF filter to '%s' (%s)\n",
            bpf, daq_get_error(daq_mod, daq_hand));

    return (err == DAQ_SUCCESS);
}

bool SFDAQInstance::start()
{
    int err;

    // The BPF can be compiled either during daq_set_filter() or daq_start(),
    // so protect the thread-unsafe BPF scanner/compiler in both places.
    {
        std::lock_guard<std::mutex> lock(bpf_gate);
        err = daq_start(daq_mod, daq_hand);
    }

    if (err)
        ErrorMessage("Can't start DAQ (%d) - %s\n", err, daq_get_error(daq_mod, daq_hand));
    else
        daq_dlt = daq_get_datalink_type(daq_mod, daq_hand);

    get_tunnel_capabilities();

    return (err == DAQ_SUCCESS);
}

void SFDAQInstance::get_tunnel_capabilities()
{
    daq_tunnel_mask = 0;
    if (daq_mod && daq_hand)
    {
        uint32_t caps = daq_get_capabilities(daq_mod, daq_hand);

        if (caps & DAQ_CAPA_DECODE_GTP)
        {
            daq_tunnel_mask |= TUNNEL_GTP;
        }
        if (caps & DAQ_CAPA_DECODE_TEREDO)
        {
            daq_tunnel_mask |= TUNNEL_TEREDO;
        }
        if (caps & DAQ_CAPA_DECODE_GRE)
        {
            daq_tunnel_mask |= TUNNEL_GRE;
        }
        if (caps & DAQ_CAPA_DECODE_4IN4)
        {
            daq_tunnel_mask |= TUNNEL_4IN4;
        }
        if (caps & DAQ_CAPA_DECODE_6IN4)
        {
            daq_tunnel_mask |= TUNNEL_6IN4;
        }
        if (caps & DAQ_CAPA_DECODE_4IN6)
        {
            daq_tunnel_mask |= TUNNEL_4IN6;
        }
        if (caps & DAQ_CAPA_DECODE_6IN6)
        {
            daq_tunnel_mask |= TUNNEL_6IN6;
        }
        if (caps & DAQ_CAPA_DECODE_MPLS)
        {
            daq_tunnel_mask |= TUNNEL_MPLS;
        }
    }
}

bool SFDAQInstance::get_tunnel_bypass(uint8_t proto)
{
    return (daq_tunnel_mask & proto) != 0;
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

static int metacallback(void *user, const DAQ_MetaHdr_t* hdr, const uint8_t* data)
{
    DataBus::publish(DAQ_META_EVENT, user, hdr->type, data);
    return 0;
}

int SFDAQInstance::acquire(int max, DAQ_Analysis_Func_t callback)
{
    int err = daq_acquire_with_meta(daq_mod, daq_hand, max, callback, metacallback, nullptr);

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
    int err = daq_inject(daq_mod, daq_hand, h, buf, len, rev);
#ifdef DEBUG_MSGS
    if (err)
        LogMessage("Can't inject (%d) - %s\n", err, daq_get_error(daq_mod, daq_hand));
#endif
    return err;
}

bool SFDAQInstance::break_loop(int error)
{
    if (error)
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

int SFDAQInstance::query_flow(const DAQ_PktHdr_t* hdr, DAQ_QueryFlow_t* query)
{
    return daq_query_flow(daq_mod, daq_hand, hdr, query);
}

int SFDAQInstance::modify_flow_opaque(const DAQ_PktHdr_t* hdr, uint32_t opaque)
{
    DAQ_ModFlow_t mod;

    mod.type = DAQ_MODFLOW_TYPE_OPAQUE;
    mod.length = sizeof(opaque);
    mod.value = &opaque;

    return daq_modify_flow(daq_mod, daq_hand, hdr, &mod);
}

int SFDAQInstance::modify_flow_pkt_trace(const DAQ_PktHdr_t* hdr, uint8_t verdict_reason,
    uint8_t* buff, uint32_t buff_len)
{
    DAQ_ModFlow_t mod;
    DAQ_ModFlowPktTrace_t mod_tr;
    mod_tr.vreason = verdict_reason;
    mod_tr.pkt_trace_data_len = buff_len;
    mod_tr.pkt_trace_data = buff;
    mod.type = DAQ_MODFLOW_TYPE_PKT_TRACE;
    mod.length = sizeof(DAQ_ModFlowPktTrace_t);
    mod.value = (void*)&mod_tr;
    return daq_modify_flow(daq_mod, daq_hand, hdr, &mod);
}

// FIXIT-L X Add Snort flag definitions for callers to use and translate/pass them through to
// the DAQ module
int SFDAQInstance::add_expected(const Packet* ctrlPkt, const SfIp* cliIP, uint16_t cliPort,
        const SfIp* srvIP, uint16_t srvPort, IpProtocol protocol, unsigned timeout_ms, unsigned /* flags */)
{
    DAQ_Data_Channel_Params_t daq_params;
    DAQ_DP_key_t dp_key;

    dp_key.src_af = cliIP->get_family();
    if (cliIP->is_ip4())
        dp_key.sa.src_ip4.s_addr = cliIP->get_ip4_value();
    else
        memcpy(&dp_key.sa.src_ip6, cliIP->get_ip6_ptr(), sizeof(dp_key.sa.src_ip6));
    dp_key.src_port = cliPort;

    dp_key.dst_af = srvIP->get_family();
    if (srvIP->is_ip4())
        dp_key.da.dst_ip4.s_addr = srvIP->get_ip4_value();
    else
        memcpy(&dp_key.da.dst_ip6, srvIP->get_ip6_ptr(), sizeof(dp_key.da.dst_ip6));
    dp_key.dst_port = srvPort;

    dp_key.protocol = (uint8_t) protocol;
    dp_key.vlan_cnots = 1;
    if (ctrlPkt->proto_bits & PROTO_BIT__VLAN)
        dp_key.vlan_id = layer::get_vlan_layer(ctrlPkt)->vid();
    else
        dp_key.vlan_id = 0xFFFF;

    if (ctrlPkt->proto_bits & PROTO_BIT__GTP)
        dp_key.tunnel_type = DAQ_DP_TUNNEL_TYPE_GTP_TUNNEL;
    else if (ctrlPkt->proto_bits & PROTO_BIT__MPLS)
        dp_key.tunnel_type = DAQ_DP_TUNNEL_TYPE_MPLS_TUNNEL;
/*
    else if ( ctrlPkt->encapsulated )
        dp_key.tunnel_type = DAQ_DP_TUNNEL_TYPE_OTHER_TUNNEL;
*/
    else
        dp_key.tunnel_type = DAQ_DP_TUNNEL_TYPE_NON_TUNNEL;

    memset(&daq_params, 0, sizeof(daq_params));
    daq_params.timeout_ms = timeout_ms;
/*
    if (flags & DAQ_DC_FLOAT)
        daq_params.flags |= DAQ_DATA_CHANNEL_FLOAT;
    if (flags & DAQ_DC_ALLOW_MULTIPLE)
        daq_params.flags |= DAQ_DATA_CHANNEL_ALLOW_MULTIPLE;
    if (flags & DAQ_DC_PERSIST)
        daq_params.flags |= DAQ_DATA_CHANNEL_PERSIST;
*/

    return daq_dp_add_dc(daq_mod, daq_hand, ctrlPkt->pkth, &dp_key, nullptr, &daq_params);
}
