//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// sfdaq.h author Michael Altizer <mialtize@cisco.com>

#ifndef SFDAQ_INSTANCE_H
#define SFDAQ_INSTANCE_H

#include <daq_common.h>

#include <string>

#include "main/snort_types.h"
#include "protocols/protocol_ids.h"

struct SFDAQConfig;

namespace snort
{
struct Packet;
struct SfIp;

class SFDAQInstance
{
public:
    SFDAQInstance(const char* intf, unsigned id, const SFDAQConfig*);
    ~SFDAQInstance();

    bool init(DAQ_Config_h, const std::string& bpf_string);

    bool start();
    bool was_started() const;
    bool stop();
    void reload();

    DAQ_RecvStatus receive_messages(unsigned max_recv);
    DAQ_Msg_h next_message()
    {
        if (curr_batch_idx < curr_batch_size)
            return daq_msgs[curr_batch_idx++];
        return nullptr;
    }
    int finalize_message(DAQ_Msg_h msg, DAQ_Verdict verdict);
    const char* get_error();

    int get_base_protocol() const;
    uint32_t get_batch_size() const { return batch_size; }
    uint32_t get_pool_available() const { return pool_available; }
    const char* get_input_spec() const;
    const DAQ_Stats_t* get_stats();

    bool can_inject() const;
    bool can_inject_raw() const;
    bool can_replace() const;
    bool can_start_unprivileged() const;
    SO_PUBLIC bool can_whitelist() const;

    int inject(DAQ_Msg_h, int rev, const uint8_t* buf, uint32_t len);
    bool interrupt();

    SO_PUBLIC int ioctl(DAQ_IoctlCmd cmd, void *arg, size_t arglen);
    SO_PUBLIC int modify_flow_opaque(DAQ_Msg_h, uint32_t opaque);
    int set_packet_verdict_reason(DAQ_Msg_h msg, uint8_t verdict_reason);
    int set_packet_trace_data(DAQ_Msg_h, uint8_t* buff, uint32_t buff_len);
    int add_expected(const Packet* ctrlPkt, const SfIp* cliIP, uint16_t cliPort,
            const SfIp* srvIP, uint16_t srvPort, IpProtocol, unsigned timeout_ms,
            unsigned flags);
    bool get_tunnel_bypass(uint16_t proto);

private:
    void get_tunnel_capabilities();

    std::string input_spec;
    uint32_t instance_id;
    DAQ_Instance_h instance = nullptr;
    DAQ_Msg_h* daq_msgs;
    unsigned curr_batch_size = 0;
    unsigned curr_batch_idx = 0;
    uint32_t batch_size;
    uint32_t pool_size = 0;
    uint32_t pool_available = 0;
    int dlt = -1;
    DAQ_Stats_t daq_instance_stats = { };
    uint16_t daq_tunnel_mask = 0;
};
}
#endif

