//--------------------------------------------------------------------------
// Copyright (C) 2017-2025 Cisco and/or its affiliates. All rights reserved.
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
#include <vector>

#include "main/snort_types.h"
#include "packet_io/packet_constraints.h"
#include "protocols/ipv6.h"
#include "protocols/protocol_ids.h"
#include "sfip/sf_ip.h"
#include "time/clock_defs.h"
#include "time/stopwatch.h"

namespace snort
{
struct Packet;

class PacketTracer
{
public:
    PacketTracer();
    virtual ~PacketTracer();

    typedef uint8_t TracerMute;

    // static functions
    static void set_log_file(const std::string&);
    static void thread_init();
    static void thread_term();

    static void dump(char* output_buff, unsigned int len);
    static void dump(Packet*);
    static void daq_dump(Packet*);

    static void configure(bool status, const std::string& file_name);
    static void set_constraints(const PacketConstraints* constraints);
    static void activate(const snort::Packet&);

    static SO_PUBLIC void pause();
    static SO_PUBLIC void unpause();
    static SO_PUBLIC bool is_paused();

#ifdef _WIN64
    static SO_PUBLIC bool is_active();
    static SO_PUBLIC bool is_daq_activated();
#else
    static bool is_active()
    { return s_pkt_trace ? s_pkt_trace->active : false; }

    static bool is_daq_activated()
    { return s_pkt_trace ? s_pkt_trace->daq_activated : false; }
#endif

    static SO_PUBLIC TracerMute get_mute();

    static SO_PUBLIC void log(const char* format, ...) __attribute__((format (printf, 1, 2)));
    static SO_PUBLIC void log(TracerMute, const char* format, ...) __attribute__((format (printf, 2, 3)));
    static SO_PUBLIC void log_msg_only(const char* format, ...) __attribute__((format (printf, 1, 2)));

    static SO_PUBLIC void daq_log(const char* format, ...) __attribute__((format (printf, 1, 2)));

    static SO_PUBLIC void start_timer();
    static SO_PUBLIC void restart_timer();
    static SO_PUBLIC void reset_timer();

    static SO_PUBLIC uint64_t get_time();

protected:
#ifndef _WIN64
    static SO_PUBLIC THREAD_LOCAL PacketTracer* s_pkt_trace;
#endif

    // non-static variable
    Stopwatch<SnortClock>* pt_timer = nullptr;
    FILE* log_fh = stdout;

    char* buffer;
    char* daq_buffer;
    char* debug_session;

    std::vector<bool> mutes;

    unsigned buff_len = 0;
    unsigned daq_buff_len = 0;
    unsigned pause_count = 0;

    bool user_enabled = false;
    bool daq_activated = false;
    bool shell_enabled = false;
    bool active = false;

    std::string debugstr;
    PacketConstraints constraints;

    // static functions
    template<typename T = PacketTracer> static void _thread_init();

    // non-static functions
    void log_va(const char*, va_list, bool, bool msg_only = false);
    void populate_buf(const char*, va_list, char*, uint32_t&);
    void add_ip_header_info(const snort::Packet&);
    void add_eth_header_info(const snort::Packet&);
    void add_packet_type_info(const snort::Packet&);
    void update_constraints(const PacketConstraints* constraints);
    const char *get_debug_session() { return debugstr.c_str(); }

    void open_file();
    virtual void dump_to_daq(Packet*);
    void reset(bool);
};

struct PacketTracerSuspend
{
    PacketTracerSuspend()
    { PacketTracer::pause(); }

    ~PacketTracerSuspend()
    { PacketTracer::unpause(); }
};

}
#endif
