//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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

// sfdaq_instance.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfdaq_instance.h"

#include <daq.h>

#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "protocols/packet.h"
#include "protocols/vlan.h"

#include "sfdaq_config.h"
#include "sfdaq_module.h"

using namespace snort;

SFDAQInstance::SFDAQInstance(const char* input, unsigned id, const SFDAQConfig* cfg)
{
    if (input)
        input_spec = input;
    // The Snort instance ID is 0-based while the DAQ ID is 1-based, so adjust accordingly.
    instance_id = id + 1;
    batch_size = cfg->get_batch_size();
    daq_msgs = new DAQ_Msg_h[batch_size];
}

SFDAQInstance::~SFDAQInstance()
{
    delete[] daq_msgs;
    if (instance)
        daq_instance_destroy(instance);
}

static bool DAQ_ValidateInstance(DAQ_Instance_h instance)
{
    uint32_t caps = daq_instance_get_capabilities(instance);

    if (!SnortConfig::get_conf()->adaptor_inline_mode())
        return true;

    if (!(caps & DAQ_CAPA_BLOCK))
        ParseWarning(WARN_DAQ, "inline mode configured but DAQ can't block packets.\n");

    return true;
}

bool SFDAQInstance::init(DAQ_Config_h daqcfg, const std::string& bpf_string)
{
    char buf[256] = "";
    int rval;

    // Reuse the main DAQ instance configuration with the input specification specific to this
    // instance.  Also, configure the DAQ instance ID in the multi-instance case.
    daq_config_set_input(daqcfg, input_spec.c_str());
    if (daq_config_get_total_instances(daqcfg) > 0)
        daq_config_set_instance_id(daqcfg, instance_id);
    if ((rval = daq_instance_instantiate(daqcfg, &instance, buf, sizeof(buf))) != DAQ_SUCCESS)
    {
        ErrorMessage("Couldn't construct a DAQ instance: %s (%d)\n", buf, rval);
        return false;
    }

    if (!DAQ_ValidateInstance(instance))
        FatalError("DAQ configuration incompatible with intended operation.\n");

    if (!bpf_string.empty())
    {
        rval = daq_instance_set_filter(instance, bpf_string.c_str());
        if (rval != DAQ_SUCCESS)
            FatalError("Couldn't set DAQ instance BPF filter to '%s': %s (%d)\n",
                bpf_string.c_str(), daq_instance_get_error(instance), rval);
    }

    return true;
}

void SFDAQInstance::reload()
{
    if (!instance)
        return;

    void* new_config = nullptr;
    if (daq_instance_config_load(instance, &new_config) == DAQ_SUCCESS)
    {
        void* old_config = nullptr;
        if (daq_instance_config_swap(instance, new_config, &old_config) == DAQ_SUCCESS)
            daq_instance_config_free(instance, old_config);
        else
            daq_instance_config_free(instance, new_config);
    }
}

const char* SFDAQInstance::get_input_spec() const
{
    return input_spec.c_str();
}

// That distinction does not hold with datalink types.  Snort must use whatever
// datalink type the DAQ coughs up as its base protocol decoder.  For pcaps,
// the datalink type in the file must be used - which may not be known until
// start.  The value is cached here since it used for packet operations like
// logging and is needed at shutdown.  This avoids sequencing issues.
int SFDAQInstance::get_base_protocol() const
{
    return dlt;
}

bool SFDAQInstance::can_inject() const
{
    return (daq_instance_get_capabilities(instance) & DAQ_CAPA_INJECT) != 0;
}

bool SFDAQInstance::can_inject_raw() const
{
    return (daq_instance_get_capabilities(instance) & DAQ_CAPA_INJECT_RAW) != 0;
}

bool SFDAQInstance::can_replace() const
{
    return (daq_instance_get_capabilities(instance) & DAQ_CAPA_REPLACE) != 0;
}

bool SFDAQInstance::can_start_unprivileged() const
{
    return (daq_instance_get_capabilities(instance) & DAQ_CAPA_UNPRIV_START) != 0;
}

bool SFDAQInstance::can_whitelist() const
{
    return (daq_instance_get_capabilities(instance) & DAQ_CAPA_WHITELIST) != 0;
}

bool SFDAQInstance::start()
{
    int rval = daq_instance_start(instance);
    if (rval != DAQ_SUCCESS)
    {
        ErrorMessage("Couldn't start DAQ instance: %s (%d)\n", daq_instance_get_error(instance), rval);
        return false;
    }

    DAQ_MsgPoolInfo_t mpool_info;
    rval = daq_instance_get_msg_pool_info(instance, &mpool_info);
    if (rval != DAQ_SUCCESS)
    {
        ErrorMessage("Couldn't query DAQ message pool info: %s (%d)\n", daq_instance_get_error(instance), rval);
        stop();
        return false;
    }
    pool_size = mpool_info.size;
    pool_available = mpool_info.available;
    assert(pool_size == pool_available);
    if (SnortConfig::log_verbose())
    {
        LogMessage("Instance %d daq pool size: %d\n", get_instance_id(), pool_size);
        LogMessage("Instance %d daq batch size: %d\n", get_instance_id(), batch_size);
    }
    dlt = daq_instance_get_datalink_type(instance);
    get_tunnel_capabilities();

    return (rval == DAQ_SUCCESS);
}

DAQ_RecvStatus SFDAQInstance::receive_messages(unsigned max_recv)
{
    assert(max_recv <= batch_size);

    if (max_recv > pool_available)
        max_recv = pool_available;

    DAQ_RecvStatus rstat;
    curr_batch_size = daq_instance_msg_receive(instance, max_recv, daq_msgs, &rstat);
    pool_available -= curr_batch_size;
    curr_batch_idx = 0;

    return rstat;
}

int SFDAQInstance::finalize_message(DAQ_Msg_h msg, DAQ_Verdict verdict)
{
    int rval = daq_instance_msg_finalize(instance, msg, verdict);
    if (rval == DAQ_SUCCESS)
        pool_available++;
    return rval;
}

const char* SFDAQInstance::get_error()
{
    return daq_instance_get_error(instance);
}

void SFDAQInstance::get_tunnel_capabilities()
{
    daq_tunnel_mask = 0;
    if (instance)
    {
        uint32_t caps = daq_instance_get_capabilities(instance);

        if (caps & DAQ_CAPA_DECODE_GTP)
            daq_tunnel_mask |= TUNNEL_GTP;
        if (caps & DAQ_CAPA_DECODE_TEREDO)
            daq_tunnel_mask |= TUNNEL_TEREDO;
        if (caps & DAQ_CAPA_DECODE_VXLAN)
            daq_tunnel_mask |= TUNNEL_VXLAN;
        if (caps & DAQ_CAPA_DECODE_GRE)
            daq_tunnel_mask |= TUNNEL_GRE;
        if (caps & DAQ_CAPA_DECODE_4IN4)
            daq_tunnel_mask |= TUNNEL_4IN4;
        if (caps & DAQ_CAPA_DECODE_6IN4)
            daq_tunnel_mask |= TUNNEL_6IN4;
        if (caps & DAQ_CAPA_DECODE_4IN6)
            daq_tunnel_mask |= TUNNEL_4IN6;
        if (caps & DAQ_CAPA_DECODE_6IN6)
            daq_tunnel_mask |= TUNNEL_6IN6;
        if (caps & DAQ_CAPA_DECODE_MPLS)
            daq_tunnel_mask |= TUNNEL_MPLS;
        if (caps & DAQ_CAPA_DECODE_GENEVE)
            daq_tunnel_mask |= TUNNEL_GENEVE;
    }
}

bool SFDAQInstance::get_tunnel_bypass(uint16_t proto)
{
    return (daq_tunnel_mask & proto) != 0;
}

bool SFDAQInstance::was_started() const
{
    if (!instance)
        return false;

    DAQ_State s = daq_instance_check_status(instance);
    return (s == DAQ_STATE_STARTED);
}

bool SFDAQInstance::stop()
{
    assert(pool_size == pool_available);

    if (!was_started())
        return true;

    int rval = daq_instance_stop(instance);

    if (rval != DAQ_SUCCESS)
        LogMessage("Couldn't stop DAQ instance: %s (%d)\n", daq_instance_get_error(instance), rval);

    return (rval == DAQ_SUCCESS);
}

int SFDAQInstance::inject(DAQ_Msg_h msg, int rev, const uint8_t* buf, uint32_t len)
{
    int rval = daq_instance_inject_relative(instance, msg, buf, len, rev);
#ifdef DEBUG_MSGS
    if (rval != DAQ_SUCCESS)
        LogMessage("Couldn't inject on DAQ instance: %s (%d)\n", daq_instance_get_error(instance), rval);
#endif
    return rval;
}

bool SFDAQInstance::interrupt()
{
    return (daq_instance_interrupt(instance) == DAQ_SUCCESS);
}

const DAQ_Stats_t* SFDAQInstance::get_stats()
{
    if (instance)
    {
        int rval = daq_instance_get_stats(instance, &daq_instance_stats);
        if (rval != DAQ_SUCCESS)
            LogMessage("Couldn't query DAQ stats: %s (%d)\n", daq_instance_get_error(instance), rval);
    }

    return &daq_instance_stats;
}

int SFDAQInstance::ioctl(DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    return daq_instance_ioctl(instance, cmd, arg, arglen);
}

int SFDAQInstance::modify_flow_opaque(DAQ_Msg_h msg, uint32_t opaque)
{
    DIOCTL_SetFlowOpaque d_sfo;
    d_sfo.msg = msg;
    d_sfo.value = opaque;

    return daq_instance_ioctl(instance, DIOCTL_SET_FLOW_OPAQUE, &d_sfo, sizeof(d_sfo));
}

int SFDAQInstance::set_packet_verdict_reason(DAQ_Msg_h msg, uint8_t verdict_reason)
{
    DIOCTL_SetPacketVerdictReason d_spvr;

    d_spvr.msg = msg;
    d_spvr.verdict_reason = verdict_reason;

    return daq_instance_ioctl(instance, DIOCTL_SET_PACKET_VERDICT_REASON, &d_spvr, sizeof(d_spvr));
}

int SFDAQInstance::set_packet_trace_data(DAQ_Msg_h msg, uint8_t* buff, uint32_t buff_len)
{
    DIOCTL_SetPacketTraceData d_sptd;

    d_sptd.msg = msg;
    d_sptd.trace_data_len = buff_len;
    d_sptd.trace_data = buff;

    return daq_instance_ioctl(instance, DIOCTL_SET_PACKET_TRACE_DATA, &d_sptd, sizeof(d_sptd));
}

// FIXIT-L X Add Snort flag definitions for callers to use and translate/pass them through to
// the DAQ module
int SFDAQInstance::add_expected(const Packet* ctrlPkt, const SfIp* cliIP, uint16_t cliPort,
        const SfIp* srvIP, uint16_t srvPort, IpProtocol protocol, unsigned timeout_ms, unsigned flags)
{
    DIOCTL_CreateExpectedFlow d_cef;

    d_cef.ctrl_msg = ctrlPkt->daq_msg;

    /* Populate the expected flow key */
    DAQ_EFlow_Key_t* key = &d_cef.key;

    key->src_af = cliIP->get_family();
    if (cliIP->is_ip4())
        key->sa.src_ip4.s_addr = cliIP->get_ip4_value();
    else
        memcpy(&key->sa.src_ip6, cliIP->get_ip6_ptr(), sizeof(key->sa.src_ip6));
    key->src_port = cliPort;

    key->dst_af = srvIP->get_family();
    if (srvIP->is_ip4())
        key->da.dst_ip4.s_addr = srvIP->get_ip4_value();
    else
        memcpy(&key->da.dst_ip6, srvIP->get_ip6_ptr(), sizeof(key->da.dst_ip6));
    key->dst_port = srvPort;

    // FIXIT-M The key address_space_id is not currently being populated!

    if (ctrlPkt->proto_bits & PROTO_BIT__GTP)
        key->tunnel_type = DAQ_EFLOW_TUNNEL_TYPE_GTP_TUNNEL;
    else if (ctrlPkt->proto_bits & PROTO_BIT__MPLS)
        key->tunnel_type = DAQ_EFLOW_TUNNEL_TYPE_MPLS_TUNNEL;
    // FIXIT-L Need to figure out the right way to determine "Other" encapsulation
/*
    else if ( ctrlPkt->encapsulated )
        key->tunnel_type = DAQ_EFLOW_TUNNEL_TYPE_OTHER_TUNNEL;
*/
    else
        key->tunnel_type = DAQ_EFLOW_TUNNEL_TYPE_NON_TUNNEL;

    key->protocol = (uint8_t) protocol;
    if (ctrlPkt->proto_bits & PROTO_BIT__VLAN)
        key->vlan_id = layer::get_vlan_layer(ctrlPkt)->vid();
    else
        key->vlan_id = 0xFFFF;
    key->vlan_cnots = 1;

    d_cef.flags = 0;

    if (flags & DAQ_EFLOW_ALLOW_MULTIPLE)
        d_cef.flags |= DAQ_EFLOW_ALLOW_MULTIPLE;

    if (flags & DAQ_EFLOW_BIDIRECTIONAL)
        d_cef.flags |= DAQ_EFLOW_BIDIRECTIONAL;

    if (flags & DAQ_EFLOW_PERSIST)
        d_cef.flags |= DAQ_EFLOW_PERSIST;
/*
    if (flags & DAQ_DC_FLOAT)
        d_cef.flags |= DAQ_EFLOW_FLOAT;
    if (flags & DAQ_DC_ALLOW_MULTIPLE)
        d_cef.flags |= DAQ_EFLOW_ALLOW_MULTIPLE;
*/
    d_cef.timeout_ms = timeout_ms;
    // Opaque data blob for expected flows is currently unused/unimplemented
    d_cef.data = nullptr;
    d_cef.length = 0;

    daq_stats.expected_flows++;

    return daq_instance_ioctl(instance, DIOCTL_CREATE_EXPECTED_FLOW, &d_cef, sizeof(d_cef));
}
