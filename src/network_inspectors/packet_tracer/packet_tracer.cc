//--------------------------------------------------------------------------
// Copyright (C) 2017-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/ips_context.h"
#include "log/log.h"
#include "log/messages.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq_instance.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/ip.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

// FIXIT-M refactor the way this is used so all methods are members called against this pointer
THREAD_LOCAL PacketTracer* snort::s_pkt_trace = nullptr;

THREAD_LOCAL Stopwatch<SnortClock>* snort::pt_timer = nullptr;

// so modules can register regardless of when packet trace is activated
static THREAD_LOCAL struct{ unsigned val = 0; } global_mutes;

static std::string log_file = "-";
static bool config_status = false;

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------

void PacketTracer::set_log_file(const std::string& file)
{ log_file = file; }

// template needed for unit tests
template<typename T> void PacketTracer::_thread_init()
{
    if ( s_pkt_trace == nullptr )
        s_pkt_trace = new T();

    if ( pt_timer == nullptr )
        pt_timer = new Stopwatch<SnortClock>;

    s_pkt_trace->mutes.resize(global_mutes.val, false);
    s_pkt_trace->open_file();
    s_pkt_trace->user_enabled = config_status;
}
template void PacketTracer::_thread_init<PacketTracer>();

void PacketTracer::thread_init()
{ _thread_init(); }

void PacketTracer::thread_term()
{
    if ( s_pkt_trace )
    {
        delete s_pkt_trace;
        s_pkt_trace = nullptr;
    }

    if (pt_timer)
    {
        delete pt_timer;
        pt_timer = nullptr;
    }
}

void PacketTracer::dump(char* output_buff, unsigned int len)
{
    if (is_paused())
        return;

    if (output_buff)
        memcpy(output_buff, s_pkt_trace->buffer,
            (len < s_pkt_trace->buff_len + 1 ? len : s_pkt_trace->buff_len + 1));

    s_pkt_trace->reset(false);
}

void PacketTracer::dump(Packet* p)
{
    if (is_paused())
        return;

    if ((s_pkt_trace->buff_len > 0)
        and (s_pkt_trace->user_enabled or s_pkt_trace->shell_enabled))
    {
        const char* drop_reason = p->active->get_drop_reason();
        if (drop_reason)
            PacketTracer::log("Verdict Reason: %s, %s\n", drop_reason, p->active->get_action_string() );
        LogMessage(s_pkt_trace->log_fh, "%s\n", s_pkt_trace->buffer);
    }

    s_pkt_trace->reset(false);
}

void PacketTracer::daq_dump(Packet *p)
{
    if (is_paused())
        return;

    if (s_pkt_trace->daq_activated)
        s_pkt_trace->dump_to_daq(p);

    s_pkt_trace->reset(true);
}

void PacketTracer::daq_log(const char* format, ...)
{
    if (is_paused())
        return;

    va_list ap;
    va_start(ap, format);
    s_pkt_trace->log_va(format, ap, true);
    va_end(ap);
}

void PacketTracer::log(const char* format, ...)
{
    if (is_paused())
        return;

    va_list ap;
    va_start(ap, format);
    s_pkt_trace->log_va(format, ap, false);
    va_end(ap);
}

void PacketTracer::log(TracerMute mute, const char* format, ...)
{
    if ( s_pkt_trace->mutes[mute] )
        return; // logged under this mute once. don't log again until dump.

    va_list ap;
    va_start(ap, format);
    s_pkt_trace->log_va(format, ap, false);
    va_end(ap);

    s_pkt_trace->mutes[mute] = true;
}

bool PacketTracer::is_paused()
{
    if ( s_pkt_trace and s_pkt_trace->pause_count )
        return true;
    return false;
}

void PacketTracer::set_constraints(const PacketConstraints* constraints)
{
    if (!s_pkt_trace)
        return;

    if (!constraints)
    {
        LogMessage("Debugging packet tracer disabled\n");
        s_pkt_trace->shell_enabled = false;
    }
    else
        s_pkt_trace->update_constraints(constraints);
}

void PacketTracer::configure(bool status, const std::string& file_name)
{

    log_file = file_name;
    config_status = status;
}

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

void PacketTracer::activate(const Packet& p)
{
    if (!s_pkt_trace)
        return;

    if ( p.pkth->flags &  DAQ_PKT_FLAG_TRACE_ENABLED )
        s_pkt_trace->daq_activated = true;
    else
        s_pkt_trace->daq_activated = false;

    if (s_pkt_trace->user_enabled or s_pkt_trace->shell_enabled)
    {
        if (s_pkt_trace->shell_enabled and
                !s_pkt_trace->constraints.packet_match(p))
        {
            s_pkt_trace->active = false;
            return;
        }

        if (!p.ptrs.ip_api.is_ip())
        {
            s_pkt_trace->add_eth_header_info(p);
            s_pkt_trace->add_packet_type_info(p);
        }
        else
        {
            s_pkt_trace->active = true;
            s_pkt_trace->add_ip_header_info(p);
        }
    }
    else
        s_pkt_trace->active = false;
}

void PacketTracer::pt_timer_start()
{
    pt_timer->reset();
    pt_timer->start();
}

// -----------------------------------------------------------------------------
// non-static functions
// -----------------------------------------------------------------------------

// destructor
PacketTracer::~PacketTracer()
{
    if ( log_fh && log_fh != stdout )
    {
        fclose(log_fh);
        log_fh = nullptr;
    }
}

void PacketTracer::populate_buf(const char* format, va_list ap, char* buffer, uint32_t& buff_len)
{
    const int buff_space = max_buff_size - buff_len;
    const int len = vsnprintf(buffer + buff_len, buff_space, format, ap);

    if (len >= 0 and len < buff_space)
        buff_len += len;
    else
        buff_len = max_buff_size - 1;
}

void PacketTracer::log_va(const char* format, va_list ap, bool daq_log)
{
    // FIXIT-L Need to find way to add 'PktTracerDbg' string as part of format string.
    std::string dbg_str;
    if (shell_enabled and !daq_log) // only add debug string during shell execution
    {
        dbg_str = "PktTracerDbg ";
        if (strcmp(format, "\n") != 0)
            dbg_str += get_debug_session();
        dbg_str += format;
        format = dbg_str.c_str();
    }

    if (daq_log)
        s_pkt_trace->populate_buf(format, ap, daq_buffer, daq_buff_len);
    else
        s_pkt_trace->populate_buf(format, ap, buffer, buff_len);
}

void PacketTracer::add_ip_header_info(const Packet& p)
{
    SfIpString sipstr;
    SfIpString dipstr;

    uint16_t sport = p.ptrs.sp;
    uint16_t dport = p.ptrs.dp;

    const SfIp* actual_sip = p.ptrs.ip_api.get_src();
    const SfIp* actual_dip = p.ptrs.ip_api.get_dst();

    IpProtocol proto = p.get_ip_proto_next();

    actual_sip->ntop(sipstr, sizeof(sipstr));
    actual_dip->ntop(dipstr, sizeof(dipstr));

    char gr_buf[32] = { '\0' };
    if (p.is_inter_group_flow())
        snprintf(gr_buf, sizeof(gr_buf), " GR=%hd-%hd", p.pkth->ingress_group,
            p.pkth->egress_group);

    if (shell_enabled)
    {
        PacketTracer::log("\n");
        snprintf(debug_session, sizeof(debug_session), "%s %hu -> %s %hu %hhu AS=%u ID=%u%s ",
            sipstr, sport, dipstr, dport, static_cast<uint8_t>(proto),
            p.pkth->address_space_id, get_instance_id(), gr_buf);
    }
    else
    {
        add_eth_header_info(p);
        PacketTracer::log("%s:%hu -> %s:%hu proto %u AS=%u ID=%u%s\n",
            sipstr, sport, dipstr, dport, static_cast<uint8_t>(proto),
            p.pkth->address_space_id, get_instance_id(), gr_buf);
    }
    add_packet_type_info(p);
}

void PacketTracer::add_packet_type_info(const Packet& p)
{
    bool is_v6 = p.ptrs.ip_api.is_ip6();
    char timestamp[TIMEBUF_SIZE];
    ts_print((const struct timeval*)&p.pkth->ts, timestamp);

    switch (p.type())
    {
        case PktType::TCP:
        {
            char tcpFlags[10];
            CreateTCPFlagString(p.ptrs.tcph, tcpFlags);

            if (p.ptrs.tcph->th_flags & TH_ACK)
                PacketTracer::log("Packet %" PRIu64 ": TCP %s, %s, seq %u, ack %u, dsize %u%s\n",
                    p.context->packet_number, tcpFlags, timestamp,
                    p.ptrs.tcph->seq(), p.ptrs.tcph->ack(), p.dsize,
                    p.is_retry() ? ", retry pkt" : "");
            else
                PacketTracer::log("Packet %" PRIu64 ": TCP %s, %s, seq %u, dsize %u%s\n",
                    p.context->packet_number, tcpFlags, timestamp, p.ptrs.tcph->seq(),
                    p.dsize,
                    p.is_retry() ? ", retry pkt" : "");
            break;
        }

        case PktType::ICMP:
        {
            const char* icmp_str = is_v6 ? "ICMPv6" : "ICMP";

            PacketTracer::log("Packet %" PRIu64 ": %s, %s, Type: %u  Code: %u \n",
                p.context->packet_number, icmp_str, timestamp,
                p.ptrs.icmph->type, p.ptrs.icmph->code);
            break;
        }

        default:
            PacketTracer::log("Packet %" PRIu64 ": %s, %s\n",
                p.context->packet_number, p.get_type(), timestamp);
            break;
    }
}

void PacketTracer::add_eth_header_info(const Packet& p)
{
    auto eh = layer::get_eth_layer(&p);
    if (eh)
    {
        if (shell_enabled)
        {
            PacketTracer::log("\n");
            char gr_buf[32] = { '\0' };
            if (p.is_inter_group_flow())
                snprintf(gr_buf, sizeof(gr_buf), " GR=%hd-%hd", p.pkth->ingress_group,
                    p.pkth->egress_group);

            snprintf(debug_session, sizeof(debug_session),
                "%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X %04X"
                " AS=%u ID=%u%s ",
                eh->ether_src[0], eh->ether_src[1], eh->ether_src[2],
                eh->ether_src[3], eh->ether_src[4], eh->ether_src[5],
                eh->ether_dst[0], eh->ether_dst[1], eh->ether_dst[2],
                eh->ether_dst[3], eh->ether_dst[4], eh->ether_dst[5],
                (uint16_t)eh->ethertype(), p.pkth->address_space_id, get_instance_id(),
                gr_buf);
            s_pkt_trace->active = true;
        }
        else
        {
            // MAC layer
            PacketTracer::log("%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X %04X\n",
                eh->ether_src[0], eh->ether_src[1], eh->ether_src[2],
                eh->ether_src[3], eh->ether_src[4], eh->ether_src[5],
                eh->ether_dst[0], eh->ether_dst[1], eh->ether_dst[2],
                eh->ether_dst[3], eh->ether_dst[4], eh->ether_dst[5],
                (uint16_t)eh->ethertype());
        }
    }
}

void PacketTracer::update_constraints(const PacketConstraints* cs)
{

    char sipstr[INET6_ADDRSTRLEN];
    char dipstr[INET6_ADDRSTRLEN];

    constraints = *cs;
    constraints.src_ip.ntop(sipstr, sizeof(sipstr));
    constraints.dst_ip.ntop(dipstr, sizeof(dipstr));
    LogMessage("Debugging packet tracer with %s-%hu and %s-%hu %hhu\n",
        sipstr, constraints.src_port, dipstr, constraints.dst_port,
        static_cast<uint8_t>(constraints.ip_proto));

    shell_enabled = true;

}

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

void PacketTracer::dump_to_daq(Packet* p)
{
    assert(p);
    p->daq_instance->set_packet_trace_data(p->daq_msg, (uint8_t *)daq_buffer, daq_buff_len + 1);
}

void PacketTracer::reset(bool daq_log)
{
    if ( daq_log )
    {
        daq_buff_len = 0;
        daq_buffer[0] = '\0';
    }
    else
    {
        buff_len = 0;
        buffer[0] = '\0';

        for ( unsigned i = 0; i < mutes.size(); i++ )
            mutes[i] = false;
    }
}

// --------------------------------------------------------------------------
// unit tests
// --------------------------------------------------------------------------

#ifdef UNIT_TEST
#include <fcntl.h>
#include <unistd.h>

class TestPacketTracer : public PacketTracer
{
public:
    static void thread_init()
    { PacketTracer::_thread_init<TestPacketTracer>(); }

    static char* get_buff()
    { return ((TestPacketTracer*)s_pkt_trace)->buffer; }

    static unsigned int get_buff_len()
    { return ((TestPacketTracer*)s_pkt_trace)->buff_len; }

    static char* get_daq_buff()
    { return ((TestPacketTracer*)s_pkt_trace)->daq_buffer; }

    static unsigned int get_daq_buff_len()
    { return ((TestPacketTracer*)s_pkt_trace)->daq_buff_len; }

    static void set_user_enable(bool status)
    { ((TestPacketTracer*)s_pkt_trace)->user_enabled = status; }

    static bool is_user_enabled()
    { return ((TestPacketTracer*)s_pkt_trace)->user_enabled; }

    static void set_daq_enable(bool status)
    { ((TestPacketTracer*)s_pkt_trace)->daq_activated = status; }

    static bool is_daq_enabled()
    { return ((TestPacketTracer*)s_pkt_trace)->daq_activated; }

    static bool is_paused()
    { return ((TestPacketTracer*)s_pkt_trace)->pause_count; }

    void dump_to_daq(Packet*) override
    { }

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
    TestPacketTracer::set_user_enable(true);
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

TEST_CASE("basic daq log", "[PacketTracer]")
{
    char test_str[] = "1234567890";
    // instantiate a packet tracer
    TestPacketTracer::thread_init();
    TestPacketTracer::set_daq_enable(true);
    TestPacketTracer::daq_log("%s", test_str);
    CHECK(!(strcmp(TestPacketTracer::get_daq_buff(), test_str)));
    CHECK((TestPacketTracer::get_daq_buff_len() == 10));
    TestPacketTracer::daq_log("%s", "ABCDEFG");
    CHECK((strcmp(TestPacketTracer::get_daq_buff(), "1234567890ABCDEFG") == 0));
    CHECK((TestPacketTracer::get_daq_buff_len() == strlen(TestPacketTracer::get_daq_buff())));

    // log empty string won't change existed buffer
    unsigned int curr_len = TestPacketTracer::get_daq_buff_len();
    char empty_str[] = "";
    TestPacketTracer::daq_log("%s", empty_str);
    CHECK((TestPacketTracer::get_daq_buff_len() == curr_len));

    TestPacketTracer::thread_term();
}

TEST_CASE("corner cases", "[PacketTracer]")
{
    char test_str[] = "1234567890", empty_str[] = "";
    TestPacketTracer::thread_init();
    TestPacketTracer::set_user_enable(true);
    TestPacketTracer::set_daq_enable(true);
    // init length check
    CHECK((TestPacketTracer::get_buff_len() == 0));
    CHECK((TestPacketTracer::get_daq_buff_len() == 0));
    // logging empty string to start with
    TestPacketTracer::log("%s", empty_str);
    CHECK((TestPacketTracer::get_buff_len() == 0));
    TestPacketTracer::daq_log("%s", empty_str);
    CHECK((TestPacketTracer::get_daq_buff_len() == 0));

    // log messages larger than buffer size
    for(int i=0; i<1024; i++)
    {
        TestPacketTracer::log("%s", test_str);
        TestPacketTracer::daq_log("%s", test_str);
    }
    // when buffer limit is  reached, buffer length will stopped at max_buff_size-1
    CHECK((TestPacketTracer::get_buff_len() == (TestPacketTracer::max_buff_size-1)));
    CHECK((TestPacketTracer::get_daq_buff_len() == (TestPacketTracer::max_buff_size-1)));

    // continue logging will not change anything
    TestPacketTracer::log("%s", test_str);
    CHECK((TestPacketTracer::get_buff_len() == (TestPacketTracer::max_buff_size-1)));
    TestPacketTracer::daq_log("%s", test_str);
    CHECK((TestPacketTracer::get_daq_buff_len() == (TestPacketTracer::max_buff_size-1)));

    TestPacketTracer::thread_term();
}

TEST_CASE("dump", "[PacketTracer]")
{
    char test_string[TestPacketTracer::max_buff_size];
    char test_str[] = "ABCD", results[] = "ABCD3=400";

    TestPacketTracer::thread_init();
    TestPacketTracer::set_user_enable(true);
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
    CHECK(!TestPacketTracer::is_active());
    // enabled from user
    TestPacketTracer::set_user_enable(true);
    CHECK(TestPacketTracer::is_user_enabled());
    CHECK(!TestPacketTracer::is_daq_enabled());
    // enabled from DAQ
    TestPacketTracer::set_daq_enable(true);
    CHECK(TestPacketTracer::is_daq_enabled());
    // disable DAQ enable
    TestPacketTracer::set_daq_enable(false);
    CHECK(!TestPacketTracer::is_daq_enabled());
    // user configuration remain enabled
    CHECK(TestPacketTracer::is_user_enabled());

    TestPacketTracer::thread_term();
}

TEST_CASE("pause", "[PacketTracer]")
{
    char test_str[] = "1234567890";

    TestPacketTracer::thread_init();
    TestPacketTracer::set_user_enable(true);
    TestPacketTracer::pause();
    TestPacketTracer::pause();
    TestPacketTracer::pause();

    TestPacketTracer::log("%s", test_str);
    CHECK((TestPacketTracer::get_buff()[0] == '\0'));
    CHECK((TestPacketTracer::get_buff_len() == 0));

    TestPacketTracer::unpause();

    TestPacketTracer::log("%s", test_str);
    CHECK((TestPacketTracer::get_buff()[0] == '\0'));
    CHECK((TestPacketTracer::get_buff_len() == 0));

    TestPacketTracer::unpause();

    TestPacketTracer::log("%s", test_str);
    CHECK((TestPacketTracer::get_buff()[0] == '\0'));
    CHECK((TestPacketTracer::get_buff_len() == 0));

    TestPacketTracer::unpause();

    TestPacketTracer::log("%s", test_str);
    CHECK( !strcmp(TestPacketTracer::get_buff(), test_str) );
    CHECK((TestPacketTracer::get_buff_len() == 10));

    TestPacketTracer::thread_term();
}

TEST_CASE("verbosity", "[PacketTracer]")
{
    TestPacketTracer::thread_init();
    TestPacketTracer::set_user_enable(true);
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
    CHECK((val == expected));

    // reset mutes
    TestPacketTracer::dump(nullptr, 0);
    TestPacketTracer::log(mute_1, "this should log\n");
    TestPacketTracer::log(mute_2, "this should also log\n");
    val = TestPacketTracer::get_buff();
    CHECK((val == expected));

    TestPacketTracer::thread_term();
}

TEST_CASE("mute on inactive", "[PacketTracer]")
{
    global_mutes.val = 0;

    CHECK((TestPacketTracer::get_mute() == 0));
    CHECK((TestPacketTracer::get_mute() == 1));
    CHECK((TestPacketTracer::get_mute() == 2));

    // activation mid-run
    TestPacketTracer::thread_init();

    CHECK((TestPacketTracer::get_mute() == 3));
    CHECK((TestPacketTracer::get_mute() == 4));
    CHECK((TestPacketTracer::get_mute() == 5));

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
