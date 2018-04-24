//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// packet_tracer.h author Steven Baigal <sbaigal@cisco.com>

#ifndef PACKET_TRACER_H
#define PACKET_TRACER_H

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <daq_common.h>
#include <vector>

#include "main/snort_types.h"
#include "main/thread.h"
#include "protocols/ipv6.h"
#include "protocols/protocol_ids.h"
#include "sfip/sf_ip.h"

// %s %u -> %s %u %u AS=%u ID=%u
// IPv6 Port -> IPv6 Port Proto AS=ASNum ID=InstanceNum
#define PT_DEBUG_SESSION_ID_SIZE ((39+1+5+1+2+1+39+1+5+1+3+1+2+1+10+1+2+1+10)+1)

struct PTSessionConstraints
{
    snort::SfIp sip;
    int sip_flag = 0;
    snort::SfIp dip;
    int dip_flag = 0;
    uint16_t sport;
    uint16_t dport;
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;

    bool proto_match(IpProtocol& proto)
    {
        return (protocol == IpProtocol::PROTO_NOT_SET or protocol == proto);
    }
    bool port_match(uint16_t p1, uint16_t p2)
    {
        return (!sport or sport == p1) and (!dport or dport == p2);
    }
    bool ip_match(const uint32_t* ip1, const uint32_t* ip2)
    {
        return
            ((!sip_flag or !memcmp(sip.get_ip6_ptr(), ip1, sizeof(snort::ip::snort_in6_addr))) and
             (!dip_flag or !memcmp(dip.get_ip6_ptr(), ip2, sizeof(snort::ip::snort_in6_addr))));
    }

    void set(const PTSessionConstraints& src);
};

inline void PTSessionConstraints::set(const PTSessionConstraints& src)
{
    if ((sip_flag = src.sip_flag))
        sip.set(src.sip);
    if ((dip_flag = src.dip_flag))
        dip.set(src.dip);
    sport = src.sport;
    dport = src.dport;
    protocol = src.protocol;
}

namespace snort
{
struct Packet;

class PacketTracer
{
public:
    enum VerdictPriority : uint8_t
    {
        PRIORITY_UNSET = 0,
        PRIORITY_LOW = 1,
        PRIORITY_HIGH = 2
    };

    PacketTracer();
    virtual ~PacketTracer();

    typedef uint8_t TracerMute;
    static const int max_buff_size = 2048;

    // static functions 
    static void set_log_file(std::string);
    static void thread_init();
    static void thread_term();

    static void dump(char* output_buff, unsigned int len);
    static void dump(const DAQ_PktHdr_t*);

    static void configure(bool status, const std::string& file_name);
    static void set_constraints(const PTSessionConstraints* constraints);
    static void activate(const snort::Packet&);
    
    static SO_PUBLIC void pause();
    static SO_PUBLIC void unpause();
    static SO_PUBLIC bool is_paused();
    static SO_PUBLIC bool is_active();
    
    static SO_PUBLIC TracerMute get_mute();

    static SO_PUBLIC void register_verdict_reason(uint8_t reason_code, uint8_t priority);
    static SO_PUBLIC void set_reason(uint8_t);
    static SO_PUBLIC void log(const char* format, ...) __attribute__((format (printf, 1, 2)));
    static SO_PUBLIC void log(TracerMute, const char* format, ...) __attribute__((format (printf, 2, 3)));

protected:


    // non-static variable
    FILE* log_fh = stdout;
    std::vector<bool> mutes;
    char buffer[max_buff_size];
    unsigned buff_len = 0;
    uint8_t reason;

    unsigned pause_count = 0;
    bool user_enabled = false;
    bool daq_activated = false;
    bool shell_enabled = false;
    bool active = false;

    char debug_session[PT_DEBUG_SESSION_ID_SIZE];
    PTSessionConstraints info;
    
    // static functions
    template<typename T = PacketTracer> static void _thread_init();

    // non-static functions
    void log(const char*, va_list);
    void add_ip_header_info(const snort::Packet&);
    void add_eth_header_info(const snort::Packet&);
    void add_packet_type_info(const snort::Packet&);
    void update_constraints(const PTSessionConstraints* constraints);
    const char *get_debug_session() { return debug_session; }

    virtual void open_file();
    virtual void dump_to_daq(const DAQ_PktHdr_t*);
    virtual void reset();

};

SO_PUBLIC extern THREAD_LOCAL PacketTracer* s_pkt_trace;

inline bool PacketTracer::is_active() 
{ return s_pkt_trace ? s_pkt_trace->active : false; }

}
  
#endif
