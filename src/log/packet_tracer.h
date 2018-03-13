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
#include <daq_common.h>
#include <string>
#include <vector>

#include "main/snort_types.h"

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

    static void set_log_file(std::string);
    static void thread_init();
    static void thread_term();

    static void dump(char* output_buff, unsigned int len);
    static void dump(const DAQ_PktHdr_t*);

    static void add_header_info(Packet* p);

    static void enable_user();
    static void enable_daq();
    static void disable_daq();

    static SO_PUBLIC bool active();

    static SO_PUBLIC void pause();
    static SO_PUBLIC void unpause();

    static SO_PUBLIC TracerMute get_mute();

    static SO_PUBLIC void register_verdict_reason(uint8_t reason_code, uint8_t priority);
    static SO_PUBLIC void set_reason(uint8_t);
    static SO_PUBLIC void log(const char* format, ...) __attribute__((format (printf, 1, 2)));
    static SO_PUBLIC void log(TracerMute, const char* format, ...) __attribute__((format (printf, 2, 3)));

protected:
    FILE* log_fh = stdout;
    std::vector<bool> mutes;
    char buffer[max_buff_size];
    unsigned buff_len = 0;
    uint8_t reason;

    unsigned pause_count = 0;
    bool user_enabled = false;
    bool daq_enabled = false;

    virtual void open_file();
    virtual void dump_to_daq(const DAQ_PktHdr_t*);
    virtual void reset();

    static void log(const char*, va_list);
    template<typename T = PacketTracer> static void _thread_init();
};
}

#endif
