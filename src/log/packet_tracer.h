//--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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

struct Packet;

class PacketTracer
{
public:
    static void thread_init();
    static void thread_term();
    static void log(const char* format, ...) __attribute__((format (printf, 1, 2)));
    static void dump(char* output_buff=nullptr, unsigned int len=0);
    static void add_header_info(Packet* p);
#ifdef UNIT_TEST
    char* get_buff();
    int get_buff_len();
#endif
private:
    static const int max_buff_size = 2048;
    char buffer[max_buff_size];
    unsigned int buff_len = 0;
};

#endif
