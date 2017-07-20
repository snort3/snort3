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

// pkt_tracer.cc author Steven Baigal <sbaigal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_tracer.h"

#include <cstdarg>

#include "log.h"
#include "protocols/eth.h"
#include "protocols/ip.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

static THREAD_LOCAL PacketTracer* s_pkt_trace = nullptr;

void PacketTracer::thread_init()
{
    if (s_pkt_trace == nullptr)
    {
        s_pkt_trace = new PacketTracer();
    }
}

void PacketTracer::thread_term()
{
    if (s_pkt_trace)
    {
        delete s_pkt_trace;
        s_pkt_trace = nullptr;
    }
}

void PacketTracer::dump(char* output_buff, unsigned int len)
{
    if (!s_pkt_trace)
        return;
    if (output_buff)
    {
        memcpy(output_buff, s_pkt_trace->buffer,
            (len < s_pkt_trace->buff_len + 1 ? len : s_pkt_trace->buff_len + 1));
    }
    else
        printf("%s\n", s_pkt_trace->buffer);

    s_pkt_trace->buff_len = 0;
    s_pkt_trace->buffer[0] = '\0';
}

void PacketTracer::log(const char* format, ...)
{
    if (!s_pkt_trace)
        return;

    va_list ap;

    va_start(ap, format);
    const int buff_space = max_buff_size - s_pkt_trace->buff_len;
    const int len = vsnprintf(s_pkt_trace->buffer + s_pkt_trace->buff_len,
            buff_space, format, ap);
    va_end(ap);

    if (len >= 0 and len < buff_space)
    {
        s_pkt_trace->buff_len += len;
    }
    else
    {
        s_pkt_trace->buff_len = max_buff_size - 1;
    }
}

void PacketTracer::add_header_info(Packet* p)
{
    if (!s_pkt_trace)
        return;

    if ( auto eh = layer::get_eth_layer(p) )
    {
        // MAC layer
        log("%02X:%02X:%02X:%02X:%02X:%02X - ", eh->ether_src[0],
            eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
            eh->ether_src[4], eh->ether_src[5]);
        log("%02X:%02X:%02X:%02X:%02X:%02X ", eh->ether_dst[0],
            eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
            eh->ether_dst[4], eh->ether_dst[5]);
        // protocol and pkt size
        log("%04X\n", (uint16_t)eh->ethertype());
    }

    if (p->ptrs.ip_api.get_src() and p->ptrs.ip_api.get_src())
    {
        char sipstr[INET6_ADDRSTRLEN], dipstr[INET6_ADDRSTRLEN];

        p->ptrs.ip_api.get_src()->ntop(sipstr, sizeof(sipstr));
        p->ptrs.ip_api.get_dst()->ntop(dipstr, sizeof(dipstr));

        log("%s-%u - %s-%u %u\n",
            sipstr, p->ptrs.sp, dipstr, p->ptrs.dp, (unsigned)p->ptrs.ip_api.proto());
        log("Packet: %s", p->get_type());
        if (p->type() == PktType::TCP)
        {
            char tcpFlags[10];
            CreateTCPFlagString(p->ptrs.tcph, tcpFlags);
            log( " %s, seq %u, ack %u", tcpFlags,
                p->ptrs.tcph->seq(), p->ptrs.tcph->ack());
        }
        log("\n");
    }
}

#ifdef UNIT_TEST

char* PacketTracer::get_buff()
{
    return this->buffer;
}

int PacketTracer::get_buff_len()
{
    return this->buff_len;
}

#define MAX_PKT_TRACE_BUFF_SIZE 2048

TEST_CASE("basic log", "[PacketTracer]")
{
    char test_str[] = "1234567890";
    // instantiate a packet tracer
    PacketTracer::thread_init();

    // basic logging
    PacketTracer::log("%s", test_str);
    CHECK((memcmp(s_pkt_trace->get_buff(), test_str, 10) == 0));
    CHECK((s_pkt_trace->get_buff_len() == 10));
    // continue log will add message to the buffer
    PacketTracer::log("%s", "ABCDEFG");
    CHECK((strcmp(s_pkt_trace->get_buff(), "1234567890ABCDEFG") == 0));
    CHECK((s_pkt_trace->get_buff_len() == (int)strlen(s_pkt_trace->get_buff())));
    // log empty string won't change existed buffer
    int curr_len = s_pkt_trace->get_buff_len();
    char empty_str[] = "";
    PacketTracer::log("%s", empty_str);
    CHECK((s_pkt_trace->get_buff_len() == curr_len));

    PacketTracer::thread_term();
}

TEST_CASE("corner cases", "[PacketTracer]")
{
    char test_str[] = "1234567890", empty_str[] = "";
    PacketTracer::thread_init();

    // init length check
    CHECK((s_pkt_trace->get_buff_len() == 0));
    // logging empty string to start with
    PacketTracer::log("%s", empty_str);
    CHECK((s_pkt_trace->get_buff_len() == 0));

    // log messages larger than buffer size
    for(int i=0; i<1024; i++)
        PacketTracer::log("%s", test_str);
    // when buffer limit is  reached, buffer length will stopped at max_buff_size-1
    CHECK((s_pkt_trace->get_buff_len() == (MAX_PKT_TRACE_BUFF_SIZE-1)));

    // continue logging will not change anything
    PacketTracer::log("%s", test_str);
    CHECK((s_pkt_trace->get_buff_len() == (MAX_PKT_TRACE_BUFF_SIZE-1)));

    PacketTracer::thread_term();
}

TEST_CASE("dump", "[PacketTracer]")
{
    char test_string[MAX_PKT_TRACE_BUFF_SIZE];
    char test_str[] = "ABCD", results[] = "ABCD3=400";

    PacketTracer::thread_init();

    PacketTracer::log("%s%d=%d", test_str, 3, 400);
    PacketTracer::dump(test_string, MAX_PKT_TRACE_BUFF_SIZE);
    CHECK(!strcmp(test_string, results));
    CHECK((s_pkt_trace->get_buff_len() == 0));

    // dump again
    PacketTracer::dump(test_string, MAX_PKT_TRACE_BUFF_SIZE);
    CHECK(!strcmp(test_string, ""));
    CHECK((s_pkt_trace->get_buff_len() == 0));

    PacketTracer::thread_term();
}
#endif
