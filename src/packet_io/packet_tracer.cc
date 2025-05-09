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

// pkt_tracer.cc author Steven Baigal <sbaigal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_tracer.h"

#include <cstdarg>
#include <cstdio>
#include <unordered_map>
#include <sstream>

#include "detection/ips_context.h"
#include "log/messages.h"
#include "main/thread.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/ip.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"
#include "utils/util.h"

#include "active.h"
#include "sfdaq_instance.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

// FIXIT-M refactor the way this is used so all methods are members called against this pointer
#ifdef _WIN64
static THREAD_LOCAL PacketTracer* s_pkt_trace = nullptr;
#else
namespace snort
{
THREAD_LOCAL PacketTracer* PacketTracer::s_pkt_trace = nullptr;
};
#endif

// so modules can register regardless of when packet trace is activated
static THREAD_LOCAL struct{ unsigned val = 0; } global_mutes;

static std::string log_file = "-";
static bool config_status = false;

// %s %u -> %s %u %u AS=%u ID=%u GR=%hd-%hd
// IPv6 Port -> IPv6 Port Proto AS=ASNum ID=InstanceNum GR=SrcGroupNum-DstGroupNum
#define PT_DEBUG_SESSION_ID_SIZE ((39+1+5+1+2+1+39+1+5+1+3+1+2+1+10+1+2+1+10+32)+1)
static constexpr int max_buff_size = 2048;

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------

bool PacketTracer::is_active()
{ return s_pkt_trace ? s_pkt_trace->active : false; }

bool PacketTracer::is_daq_activated()
{ return s_pkt_trace ? s_pkt_trace->daq_activated : false; }

static std::string stringify_tcp_options(const Packet* const pkt)
{
    std::ostringstream oss;
    tcp::TcpOptIterator iter(pkt->ptrs.tcph, pkt);

    for (const tcp::TcpOption& opt : iter)
    {
        switch (opt.code)
        {
        case tcp::TcpOptCode::WSCALE:
            oss << "ws " << (uint16_t)opt.data[0] << ", ";
            break;
        case tcp::TcpOptCode::MAXSEG:
            oss << "mss " << ntohs(*((const uint16_t*)(opt.data)) ) << ", ";
            break;
        case tcp::TcpOptCode::SACKOK:
            oss << "sack OK, ";
            break;
        default:
            break;
        }
    }
    std::string opts = oss.str();
    if (!opts.empty())
    {
        opts.insert(0, "options [");
        opts.replace(opts.size() - 2, 2, "] ");
    }
    return opts;
}

void PacketTracer::set_log_file(const std::string& file)
{ log_file = file; }

// template needed for unit tests
template<typename T> void PacketTracer::_thread_init()
{
    assert(!s_pkt_trace);
    s_pkt_trace = new T();
}

void PacketTracer::thread_init()
{ _thread_init<PacketTracer>(); }

void PacketTracer::thread_term()
{
    delete s_pkt_trace;
    s_pkt_trace = nullptr;
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

void PacketTracer::log_msg_only(const char* format, ...)
{
    if (is_paused())
        return;

    va_list ap;
    va_start(ap, format);
    s_pkt_trace->log_va(format, ap, false, true);
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

uint64_t PacketTracer::get_time()
{ return TO_NSECS(s_pkt_trace->pt_timer->get()); }

void PacketTracer::start_timer()
{ s_pkt_trace->pt_timer->start(); }

void PacketTracer::reset_timer()
{ s_pkt_trace->pt_timer->reset(); }

void PacketTracer::restart_timer()
{
    s_pkt_trace->pt_timer->reset();
    s_pkt_trace->pt_timer->start();
}

// -----------------------------------------------------------------------------
// non-static functions
// -----------------------------------------------------------------------------

PacketTracer::PacketTracer()
{
    pt_timer = new Stopwatch<SnortClock>;
    buffer = new char[max_buff_size] { };
    daq_buffer = new char[max_buff_size] { };
    debug_session = new char[PT_DEBUG_SESSION_ID_SIZE];

    mutes.resize(global_mutes.val, false);
    open_file();
    user_enabled = config_status;
}

PacketTracer::~PacketTracer()
{
    if ( log_fh && log_fh != stdout )
    {
        fclose(log_fh);
        log_fh = nullptr;
    }
    delete[] debug_session;
    delete[] daq_buffer;
    delete[] buffer;
    delete pt_timer;
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

void PacketTracer::log_va(const char* format, va_list ap, bool daq_log, bool msg_only)
{
    // FIXIT-L Need to find way to add 'PktTracerDbg' string as part of format string.
    std::string dbg_str;
    if (shell_enabled and !daq_log) // only add debug string during shell execution
    {
        dbg_str = "PktTracerDbg ";
        if (!msg_only && (strcmp(format, "\n") != 0))
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
    std::ostringstream oss;

    uint16_t sport = p.ptrs.sp;
    uint16_t dport = p.ptrs.dp;

    const SfIp* actual_sip = p.ptrs.ip_api.get_src();
    const SfIp* actual_dip = p.ptrs.ip_api.get_dst();

    IpProtocol proto = p.get_ip_proto_next();

    actual_sip->ntop(sipstr, sizeof(sipstr));
    actual_dip->ntop(dipstr, sizeof(dipstr));

    if (shell_enabled)
    {
        PacketTracer::log("\n");

        oss << sipstr << " " << sport << " -> "
            << dipstr << " " << dport << " "
            << std::to_string(to_utype(proto))
            << " AS=" << p.pkth->address_space_id
            << " ID=" << get_relative_instance_number();

            if (p.is_inter_group_flow())
            {
                oss << " GR="
                    << p.pkth->ingress_group
                    << "-"
                    << p.pkth->egress_group;
            }

            if (p.pkth->tenant_id)
                oss << " TN=" << p.pkth->tenant_id;

        oss << " ";
        debugstr = oss.str();
    }
    else
    {
        add_eth_header_info(p);

        oss << sipstr << ":" << sport << " -> "
            << dipstr << ":" << dport << " "
            << "proto " << std::to_string(to_utype(proto))
            << " AS=" << p.pkth->address_space_id
            << " ID=" << get_relative_instance_number();

            if (p.is_inter_group_flow())
            {
                oss << " GR="
                    << p.pkth->ingress_group
                    << "-"
                    << p.pkth->egress_group;
            }

            if (p.pkth->tenant_id)
                oss << " TN=" << p.pkth->tenant_id;

        oss << "\n";
        PacketTracer::log("%s", oss.str().c_str());
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
            p.ptrs.tcph->stringify_flags(tcpFlags);

            std::string opts;
            if (p.ptrs.tcph->th_flags & TH_SYN)
                opts = stringify_tcp_options(&p);

            if (p.ptrs.tcph->th_flags & TH_ACK)
                PacketTracer::log("Packet %" PRIu64 ": TCP %s, %s, seq %u, ack %u, win %u, %sdsize %u%s\n",
                    p.context->packet_number, tcpFlags, timestamp,
                    p.ptrs.tcph->seq(), p.ptrs.tcph->ack(), p.ptrs.tcph->win(), opts.c_str(), p.dsize,
                    p.is_retry() ? ", retry pkt" : "");
            else
                PacketTracer::log("Packet %" PRIu64 ": TCP %s, %s, seq %u, win %u, %sdsize %u%s\n",
                    p.context->packet_number, tcpFlags, timestamp, p.ptrs.tcph->seq(),
                    p.ptrs.tcph->win(), opts.c_str(), p.dsize,
                    p.is_retry() ? ", retry pkt" : "");
            DAQ_PktTcpAckData_t* tcp_mack = (DAQ_PktTcpAckData_t*)p.daq_msg->meta[DAQ_PKT_META_TCP_ACK_DATA];
            if ( tcp_mack )
                PacketTracer::log("Meta_ack: ack %u, win %u\n",
                    ntohl(tcp_mack->tcp_ack_seq_num), ntohs(tcp_mack->tcp_window_size));
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
            std::ostringstream oss;
            oss << eh->to_string()
                << " AS=" << p.pkth->address_space_id
                << " ID=" << get_relative_instance_number();

            if (p.is_inter_group_flow())
            {
                oss << " GR="
                    << p.pkth->ingress_group
                    << "-"
                    << p.pkth->egress_group;
            }

            if (p.pkth->tenant_id)
                oss << " TN=" << p.pkth->tenant_id;

            oss << " ";  // Include a space before the remaining data.
            debugstr = oss.str();
            s_pkt_trace->active = true;
        }
        else
        {
            // MAC layer
            PacketTracer::log("%s\n", eh->to_string().c_str());
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

    LogMessage("Debugging packet tracer with %s-%hu and %s-%hu %hhu and tenants:%s\n",
        sipstr, constraints.src_port, dipstr, constraints.dst_port,
        static_cast<uint8_t>(constraints.ip_proto), int_vector_to_str(constraints.tenants).c_str());

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
    CHECK((TestPacketTracer::get_buff_len() == (max_buff_size-1)));
    CHECK((TestPacketTracer::get_daq_buff_len() == (max_buff_size-1)));

    // continue logging will not change anything
    TestPacketTracer::log("%s", test_str);
    CHECK((TestPacketTracer::get_buff_len() == (max_buff_size-1)));
    TestPacketTracer::daq_log("%s", test_str);
    CHECK((TestPacketTracer::get_daq_buff_len() == (max_buff_size-1)));

    TestPacketTracer::thread_term();
}

TEST_CASE("dump", "[PacketTracer]")
{
    char test_string[max_buff_size];
    char test_str[] = "ABCD", results[] = "ABCD3=400";

    TestPacketTracer::thread_init();
    TestPacketTracer::set_user_enable(true);
    TestPacketTracer::log("%s%d=%d", test_str, 3, 400);
    TestPacketTracer::dump(test_string, max_buff_size);
    CHECK(!strcmp(test_string, results));
    CHECK((TestPacketTracer::get_buff_len() == 0));

    // dump again
    TestPacketTracer::dump(test_string, max_buff_size);
    CHECK(!strcmp(test_string, ""));
    CHECK((TestPacketTracer::get_buff_len() == 0));

    TestPacketTracer::thread_term();
}

TEST_CASE("enable", "[PacketTracer]")
{
    TestPacketTracer::thread_init();
    // packet tracer is disabled by default
    CHECK(false == TestPacketTracer::is_active());
    // enabled from user
    TestPacketTracer::set_user_enable(true);
    CHECK(true == TestPacketTracer::is_user_enabled());
    CHECK(false == TestPacketTracer::is_daq_enabled());
    // enabled from DAQ
    TestPacketTracer::set_daq_enable(true);
    CHECK(true == TestPacketTracer::is_daq_enabled());
    // disable DAQ enable
    TestPacketTracer::set_daq_enable(false);
    CHECK(false == TestPacketTracer::is_daq_enabled());
    // user configuration remain enabled
    CHECK(true == TestPacketTracer::is_user_enabled());

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
