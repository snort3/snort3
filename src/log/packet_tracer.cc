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

// pkt_tracer.cc author Steven Baigal <sbaigal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_tracer.h"

#include <cstdarg>
#include <cstdio>
#include <unordered_map>

#include "packet_io/sfdaq.h"
#include "protocols/eth.h"
#include "protocols/ip.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

#include "log.h"
#include "messages.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

static const uint8_t VERDICT_REASON_NO_BLOCK = 2; /* Not blocking packet; all enum defined after this indicates blocking */
static std::unordered_map<uint8_t, uint8_t> reasons = { {VERDICT_REASON_NO_BLOCK, PacketTracer::PRIORITY_UNSET} };
    
// FIXIT-M refactor the way this is used so all methods are members called against this pointer
static THREAD_LOCAL PacketTracer* s_pkt_trace = nullptr;

// so modules can register regardless of when packet trace is activated
static THREAD_LOCAL struct{ unsigned val = 0; } global_mutes;

static std::string log_file = "-";

PacketTracer::PacketTracer()
{ reason = VERDICT_REASON_NO_BLOCK; }

void PacketTracer::register_verdict_reason(uint8_t reason_code, uint8_t priority)
{
    auto it = reasons.find(reason_code);
    assert( it == reasons.end() );

    reasons[reason_code] = priority;
}

void PacketTracer::set_log_file(std::string file)
{ log_file = file; }

void PacketTracer::open_file()
{
    if ( log_file == "-" )
        log_fh = stdout;
    else
    {
        std::string path;
        const char* fname = get_instance_file(path, log_file.c_str());
        log_fh = fopen(fname, "a+");

        if ( log_fh == nullptr )
        {
            WarningMessage("Could not open %s for packet trace logging\n", log_file.c_str());
            log_fh = stdout;
        }
    }
}

// template needed for unit tests
template<typename T> void PacketTracer::_thread_init()
{
    if ( s_pkt_trace == nullptr )
        s_pkt_trace = new T();

    s_pkt_trace->mutes.resize(global_mutes.val, false);
    s_pkt_trace->open_file();
}
template void PacketTracer::_thread_init<PacketTracer>();

void PacketTracer::thread_init()
{ _thread_init(); }

PacketTracer::~PacketTracer()
{
    if ( log_fh && log_fh != stdout )
    {
        fclose(log_fh);
        log_fh = nullptr;
    }
}

void PacketTracer::thread_term()
{
    if ( s_pkt_trace )
    {
        delete s_pkt_trace;
        s_pkt_trace = nullptr;
    }
}

void PacketTracer::dump_to_daq(const DAQ_PktHdr_t* pkt_hdr)
{
    SFDAQ::get_local_instance()->modify_flow_pkt_trace(pkt_hdr, s_pkt_trace->reason,
        (uint8_t *)s_pkt_trace->buffer, s_pkt_trace->buff_len + 1);
}

void PacketTracer::reset()
{
    buff_len = 0;
    buffer[0] = '\0';
    reason = VERDICT_REASON_NO_BLOCK;

    for ( unsigned i = 0; i < mutes.size(); i++ )
        mutes[i] = false;
}

void PacketTracer::dump(char* output_buff, unsigned int len)
{
    if (!active())
        return;

    if (output_buff)
        memcpy(output_buff, s_pkt_trace->buffer,
            (len < s_pkt_trace->buff_len + 1 ? len : s_pkt_trace->buff_len + 1));

    s_pkt_trace->reset();
}

void PacketTracer::dump(const DAQ_PktHdr_t* pkt_hdr)
{
    if (!active())
        return;

    if (s_pkt_trace->daq_enabled)
        s_pkt_trace->dump_to_daq(pkt_hdr);

    if (s_pkt_trace->user_enabled)
        LogMessage(s_pkt_trace->log_fh, "%s\n", s_pkt_trace->buffer);

    s_pkt_trace->reset();
}

void PacketTracer::set_reason(uint8_t reason)
{
    if ( !active() )
        return;

    if ( reasons[reason] > reasons[s_pkt_trace->reason] )
        s_pkt_trace->reason = reason;
}

void PacketTracer::log(const char* format, va_list ap)
{
    if ( !active() )
        return;

    const int buff_space = max_buff_size - s_pkt_trace->buff_len;
    const int len = vsnprintf(s_pkt_trace->buffer + s_pkt_trace->buff_len,
            buff_space, format, ap);

    if (len >= 0 and len < buff_space)
        s_pkt_trace->buff_len += len;
    else
        s_pkt_trace->buff_len = max_buff_size - 1;
}

void PacketTracer::log(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    log(format, ap);
    va_end(ap);
}

void PacketTracer::log(TracerMute mute, const char* format, ...)
{
    if ( s_pkt_trace->mutes[mute] )
        return; // logged under this mute once. don't log again until dump.

    va_list ap;
    va_start(ap, format);
    log(format, ap);
    va_end(ap);

    s_pkt_trace->mutes[mute] = true;
}

void PacketTracer::add_header_info(Packet* p)
{
    if (!active())
        return;

    if ( auto eh = layer::get_eth_layer(p) )
    {
        // MAC layer
        log("%02X:%02X:%02X:%02X:%02X:%02X -> ", eh->ether_src[0],
            eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
            eh->ether_src[4], eh->ether_src[5]);
        log("%02X:%02X:%02X:%02X:%02X:%02X ", eh->ether_dst[0],
            eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
            eh->ether_dst[4], eh->ether_dst[5]);
        // protocol and pkt size
        log("%04X\n", (uint16_t)eh->ethertype());
    }

    if (p->ptrs.ip_api.get_src() and p->ptrs.ip_api.get_dst())
    {
        char sipstr[INET6_ADDRSTRLEN], dipstr[INET6_ADDRSTRLEN];

        p->ptrs.ip_api.get_src()->ntop(sipstr, sizeof(sipstr));
        p->ptrs.ip_api.get_dst()->ntop(dipstr, sizeof(dipstr));

        log("%s:%hu -> %s:%hu proto %u\n",
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

bool PacketTracer::active()
{
    if ( !s_pkt_trace )
        return false;

    if ( s_pkt_trace->pause_count )
        return false;

    return s_pkt_trace->user_enabled || s_pkt_trace->daq_enabled;
}

void PacketTracer::enable_user()
{ s_pkt_trace->user_enabled = true; }

void PacketTracer::enable_daq()
{ s_pkt_trace->daq_enabled = true; }

void PacketTracer::disable_daq()
{ s_pkt_trace->daq_enabled = false; }

void PacketTracer::pause()
{ s_pkt_trace->pause_count++; }

void PacketTracer::unpause()
{
    assert(s_pkt_trace->pause_count);

    s_pkt_trace->pause_count--;
}

PacketTracer::TracerMute PacketTracer::get_mute()
{
    global_mutes.val++;
    if ( s_pkt_trace == nullptr )
        return global_mutes.val - 1;

    s_pkt_trace->mutes.push_back(false);
    return s_pkt_trace->mutes.size() - 1;
}

#ifdef UNIT_TEST
#include <fcntl.h>
#include <unistd.h>

class TestPacketTracer : public PacketTracer
{
public:
    uint8_t dump_reason = VERDICT_REASON_NO_BLOCK;

    static void thread_init()
    { PacketTracer::_thread_init<TestPacketTracer>(); }

    static char* get_buff()
    { return ((TestPacketTracer*)s_pkt_trace)->buffer; }

    static unsigned int get_buff_len()
    { return ((TestPacketTracer*)s_pkt_trace)->buff_len; }

    static bool is_user_enabled()
    { return ((TestPacketTracer*)s_pkt_trace)->user_enabled; }

    static bool is_daq_enabled()
    { return ((TestPacketTracer*)s_pkt_trace)->daq_enabled; }

    static bool is_paused()
    { return ((TestPacketTracer*)s_pkt_trace)->pause_count; }

    static uint8_t get_reason()
    { return ((TestPacketTracer*)s_pkt_trace)->reason; }

    static uint8_t get_dump_reason()
    { return ((TestPacketTracer*)s_pkt_trace)->dump_reason; }

    virtual void dump_to_daq(const DAQ_PktHdr_t*) override
    { dump_reason = reason; }

    static std::vector<bool> get_mutes()
    { return ((TestPacketTracer*)s_pkt_trace)->mutes; }

    static FILE* get_log_fh()
    { return ((TestPacketTracer*)s_pkt_trace)->log_fh; }
};

TEST_CASE("basic log", "[PacketTracer]")
{
    char test_str[] = "1234567890";
    // instantiate a packet tracer
    TestPacketTracer::thread_init();
    TestPacketTracer::enable_user();
    // basic logging
    TestPacketTracer::log("%s", test_str);
    CHECK(!(strcmp(TestPacketTracer::get_buff(), test_str)));
    CHECK((TestPacketTracer::get_buff_len() == 10));
    // continue log will add message to the buffer
    TestPacketTracer::log("%s", "ABCDEFG");
    CHECK((strcmp(TestPacketTracer::get_buff(), "1234567890ABCDEFG") == 0));
    CHECK((TestPacketTracer::get_buff_len() == strlen(TestPacketTracer::get_buff())));
    // log empty string won't change existed buffer
    unsigned int curr_len = TestPacketTracer::get_buff_len();
    char empty_str[] = "";
    TestPacketTracer::log("%s", empty_str);
    CHECK((TestPacketTracer::get_buff_len() == curr_len));

    TestPacketTracer::thread_term();
}

TEST_CASE("corner cases", "[PacketTracer]")
{
    char test_str[] = "1234567890", empty_str[] = "";
    TestPacketTracer::thread_init();
    TestPacketTracer::enable_user();
    // init length check
    CHECK((TestPacketTracer::get_buff_len() == 0));
    // logging empty string to start with
    TestPacketTracer::log("%s", empty_str);
    CHECK((TestPacketTracer::get_buff_len() == 0));

    // log messages larger than buffer size
    for(int i=0; i<1024; i++)
        TestPacketTracer::log("%s", test_str);
    // when buffer limit is  reached, buffer length will stopped at max_buff_size-1
    CHECK((TestPacketTracer::get_buff_len() == (TestPacketTracer::max_buff_size-1)));

    // continue logging will not change anything
    TestPacketTracer::log("%s", test_str);
    CHECK((TestPacketTracer::get_buff_len() == (TestPacketTracer::max_buff_size-1)));

    TestPacketTracer::thread_term();
}

TEST_CASE("dump", "[PacketTracer]")
{
    char test_string[TestPacketTracer::max_buff_size];
    char test_str[] = "ABCD", results[] = "ABCD3=400";

    TestPacketTracer::thread_init();
    TestPacketTracer::enable_user();
    TestPacketTracer::log("%s%d=%d", test_str, 3, 400);
    TestPacketTracer::dump(test_string, TestPacketTracer::max_buff_size);
    CHECK(!strcmp(test_string, results));
    CHECK((TestPacketTracer::get_buff_len() == 0));

    // dump again
    TestPacketTracer::dump(test_string, TestPacketTracer::max_buff_size);
    CHECK(!strcmp(test_string, ""));
    CHECK((TestPacketTracer::get_buff_len() == 0));

    TestPacketTracer::thread_term();
}

TEST_CASE("enable", "[PacketTracer]")
{
    TestPacketTracer::thread_init();
    // packet tracer is disabled by default
    CHECK(!TestPacketTracer::active());
    // enabled from user
    TestPacketTracer::enable_user();
    CHECK(TestPacketTracer::active());
    CHECK(TestPacketTracer::is_user_enabled());
    CHECK(!TestPacketTracer::is_daq_enabled());
    // enabled from DAQ
    TestPacketTracer::enable_daq();
    CHECK(TestPacketTracer::active());
    CHECK(TestPacketTracer::is_daq_enabled());
    // disable DAQ enable
    TestPacketTracer::disable_daq();
    CHECK(!TestPacketTracer::is_daq_enabled());
    // user configuration remain enabled
    CHECK(TestPacketTracer::active());
    CHECK(TestPacketTracer::is_user_enabled());
    
    TestPacketTracer::thread_term();
}

TEST_CASE("pause", "[PacketTracer]")
{
    char test_str[] = "1234567890";

    TestPacketTracer::thread_init();
    TestPacketTracer::enable_user();
    TestPacketTracer::pause();
    TestPacketTracer::pause();
    TestPacketTracer::pause();

    TestPacketTracer::log("%s", test_str);
    CHECK( TestPacketTracer::get_buff()[0] == '\0' );
    CHECK( TestPacketTracer::get_buff_len() == 0 );

    TestPacketTracer::unpause();

    TestPacketTracer::log("%s", test_str);
    CHECK( TestPacketTracer::get_buff()[0] == '\0' );
    CHECK( TestPacketTracer::get_buff_len() == 0 );

    TestPacketTracer::unpause();

    TestPacketTracer::log("%s", test_str);
    CHECK( TestPacketTracer::get_buff()[0] == '\0' );
    CHECK( TestPacketTracer::get_buff_len() == 0 );

    TestPacketTracer::unpause();

    TestPacketTracer::log("%s", test_str);
    CHECK( !strcmp(TestPacketTracer::get_buff(), test_str) );
    CHECK( TestPacketTracer::get_buff_len() == 10 );

    TestPacketTracer::thread_term();
}

TEST_CASE("reasons", "[PacketTracer]")
{
    TestPacketTracer::thread_init();
    TestPacketTracer::enable_daq();
    uint8_t low1 = 100, low2 = 101, high = 102;
    TestPacketTracer::register_verdict_reason(low1, PacketTracer::PRIORITY_LOW);
    TestPacketTracer::register_verdict_reason(low2, PacketTracer::PRIORITY_LOW);
    TestPacketTracer::register_verdict_reason(high, PacketTracer::PRIORITY_HIGH);
    
    // Init
    CHECK( TestPacketTracer::get_reason() == VERDICT_REASON_NO_BLOCK );
    
    // Update
    TestPacketTracer::set_reason(low1);
    CHECK( TestPacketTracer::get_reason() == low1 );
    
    // Don't update if already set
    TestPacketTracer::set_reason(VERDICT_REASON_NO_BLOCK);
    CHECK( TestPacketTracer::get_reason() == low1 );
    TestPacketTracer::set_reason(low2);
    CHECK( TestPacketTracer::get_reason() == low1 );

    // Always update for high priority
    TestPacketTracer::set_reason(high);
    CHECK( TestPacketTracer::get_reason() == high );

    // Dump resets reason
    TestPacketTracer::dump(nullptr);
    CHECK( TestPacketTracer::get_reason() == VERDICT_REASON_NO_BLOCK );

    // Dump delivers reason to daq
    CHECK( TestPacketTracer::get_dump_reason() == high );

    TestPacketTracer::thread_term();
}

TEST_CASE("verbosity", "[PacketTracer]")
{
    TestPacketTracer::thread_init();
    TestPacketTracer::enable_user();
    PacketTracer::TracerMute mute_1 = TestPacketTracer::get_mute();
    PacketTracer::TracerMute mute_2 = TestPacketTracer::get_mute();

    TestPacketTracer::log(mute_1, "this should log\n");
    TestPacketTracer::log(mute_1, "this should not log\n");
    TestPacketTracer::log(mute_1, "this should not log\n");
    TestPacketTracer::log(mute_2, "this should also log\n");
    TestPacketTracer::log(mute_2, "this should not log\n");
    TestPacketTracer::log(mute_2, "this should not log\n");

    std::string val = TestPacketTracer::get_buff();
    std::string expected = "this should log\nthis should also log\n";
    CHECK( val == expected );

    // reset mutes
    TestPacketTracer::dump(nullptr, 0);
    TestPacketTracer::log(mute_1, "this should log\n");
    TestPacketTracer::log(mute_2, "this should also log\n");
    val = TestPacketTracer::get_buff();
    CHECK( val == expected );
       
    TestPacketTracer::thread_term();
}

TEST_CASE("mute on inactive", "[PacketTracer]")
{
    global_mutes.val = 0;

    CHECK( TestPacketTracer::get_mute() == 0 );
    CHECK( TestPacketTracer::get_mute() == 1 );
    CHECK( TestPacketTracer::get_mute() == 2 );

    // activation mid-run
    TestPacketTracer::thread_init();

    CHECK( TestPacketTracer::get_mute() == 3 );
    CHECK( TestPacketTracer::get_mute() == 4 );
    CHECK( TestPacketTracer::get_mute() == 5 );

    std::vector<bool> expected = {false, false, false, false, false, false};
    CHECK( TestPacketTracer::get_mutes() == expected );

    TestPacketTracer::thread_term();
}

TEST_CASE("open stdout", "[PacketTracer]")
{
    TestPacketTracer::set_log_file("-");
    TestPacketTracer::thread_init();
    CHECK( log_file == "-" );
    CHECK( TestPacketTracer::get_log_fh() == stdout );

    TestPacketTracer::thread_term();
}

TEST_CASE("open file", "[PacketTracer]")
{
    TestPacketTracer::set_log_file("packet_tracer_tmp");
    TestPacketTracer::thread_init();
    CHECK( log_file == "packet_tracer_tmp" );

    FILE* fh = TestPacketTracer::get_log_fh();
    CHECK( fh != stdout );

    TestPacketTracer::thread_term();
    std::string path;
    remove(get_instance_file(path, "packet_tracer_tmp"));
}

#endif
