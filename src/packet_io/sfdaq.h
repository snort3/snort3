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

// sfdaq.h author Michael Altizer <mialtize@cisco.com>

#ifndef SFDAQ_H
#define SFDAQ_H

#include <daq_common.h>

#include <string>

#include "main/snort_types.h"
#include "protocols/protocol_ids.h"

namespace snort
{
struct Packet;
struct SnortConfig;
struct SfIp;

class SFDAQInstance
{
public:
    SFDAQInstance(const char* intf);
    ~SFDAQInstance();

    bool configure(const SnortConfig*);
    void set_metacallback(DAQ_Meta_Func_t);

    bool start();
    bool was_started();
    bool stop();
    void reload();
    void abort();

    int get_base_protocol();
    const char* get_interface_spec();
    const DAQ_Stats_t* get_stats();

    bool can_inject();
    bool can_inject_raw();
    bool can_replace();
    bool can_retry();
    bool can_start_unprivileged();
    SO_PUBLIC bool can_whitelist();

    int acquire(int max, DAQ_Analysis_Func_t);
    int inject(const DAQ_PktHdr_t*, int rev, const uint8_t* buf, uint32_t len);
    bool break_loop(int error);

    SO_PUBLIC int query_flow(const DAQ_PktHdr_t*, DAQ_QueryFlow_t*);
    SO_PUBLIC int modify_flow_opaque(const DAQ_PktHdr_t*, uint32_t opaque);
    int modify_flow_pkt_trace(const DAQ_PktHdr_t*, uint8_t verdict_reason,
        uint8_t* buff, uint32_t buff_len);
    int add_expected(const Packet* ctrlPkt, const SfIp* cliIP, uint16_t cliPort,
            const SfIp* srvIP, uint16_t srvPort, IpProtocol, unsigned timeout_ms,
            unsigned /* flags */);
    bool get_tunnel_bypass(uint8_t proto);

private:
    void get_tunnel_capabilities();
    bool set_filter(const char*);
    std::string interface_spec;
    void* daq_hand;
    int daq_dlt;
    int s_error;
    DAQ_Stats_t daq_stats;
    uint8_t daq_tunnel_mask;
};

class SFDAQ
{
public:
    static void load(const SnortConfig*);
    static void unload();

    static void print_types(std::ostream&);
    static const char* verdict_to_string(DAQ_Verdict verdict);
    static void init(const SnortConfig*);
    static void term();

    static const char* get_type();
    static const char* get_input_spec(const SnortConfig*, unsigned instance_id);
    static const char* default_type();
    static const DAQ_Stats_t* get_stats();

    static bool unprivileged();
    static bool can_inject();
    static bool can_inject_raw();
    static bool can_replace();
    static bool can_retry();
    SO_PUBLIC static bool get_tunnel_bypass(uint8_t proto);

    // FIXIT-M X Temporary thread-local instance helpers to be removed when no longer needed
    static void set_local_instance(SFDAQInstance*);

    SO_PUBLIC static SFDAQInstance* get_local_instance();
    SO_PUBLIC static const char* get_interface_spec();
    SO_PUBLIC static int get_base_protocol();
    SO_PUBLIC static uint32_t get_snap_len();

    static int inject(const DAQ_PktHdr_t*, int rev, const uint8_t* buf, uint32_t len);
    static bool forwarding_packet(const DAQ_PktHdr_t*);
    static bool break_loop(int error);
};
}
#endif

