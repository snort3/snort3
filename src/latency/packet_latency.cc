//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// packet_latency.cc author Joel Cornett <jocornet@cisco.com>

#include "packet_latency.h"

#include <cassert>
#include <mutex>
#include <sstream>
#include <vector>

#include "main/snort_config.h"
#include "main/thread.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"
#include "time/clock_defs.h"
#include "latency_config.h"
#include "latency_timer.h"
#include "latency_util.h"
#include "latency_stats.h"
#include "latency_rules.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

namespace packet_latency
{
// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

using DefaultClock = hr_clock;

struct Event
{
    const Packet* packet;
    bool fastpathed;
    typename DefaultClock::duration elapsed;
};

using ConfigWrapper = ReferenceWrapper<PacketLatencyConfig>;
using EventHandler = EventingWrapper<Event>;

static inline std::ostream& operator<<(std::ostream& os, const sfip_t* addr)
{
    char str[INET6_ADDRSTRLEN + 1];
    sfip_ntop(addr, str, sizeof(str));
    str[INET6_ADDRSTRLEN] = '\0';
    os << str;
    return os;
}

static inline std::ostream& operator<<(std::ostream& os, const Event& e)
{
    using std::chrono::duration_cast;
    using std::chrono::microseconds;

    os << "latency: packet timed out";
    if ( e.fastpathed )
        os << " (fastpathed): ";
    else
        os << ": ";

    os << duration_cast<microseconds>(e.elapsed).count() << " usec, [";
    os << e.packet->ptrs.ip_api.get_src() << " -> " <<
        e.packet->ptrs.ip_api.get_dst() << "]";

    return os;
}

// -----------------------------------------------------------------------------
// implementation
// -----------------------------------------------------------------------------

template<typename Clock = DefaultClock>
class Impl
{
public:
    Impl(const ConfigWrapper&, EventHandler&, EventHandler&);

    void push();
    bool pop(const Packet*);
    bool fastpath();

private:
    std::vector<LatencyTimer<Clock>> timers;
    const ConfigWrapper& config;
    EventHandler& event_handler;
    EventHandler& log_handler;
};

template<typename Clock>
inline Impl<Clock>::Impl(const ConfigWrapper& cfg, EventHandler& eh, EventHandler& lh) :
    config(cfg), event_handler(eh), log_handler(lh)
{ }

template<typename Clock>
inline void Impl<Clock>::push()
{
    using std::chrono::duration_cast;
    timers.push_back(duration_cast<typename Clock::duration>(
        config->max_time));
}

template<typename Clock>
inline bool Impl<Clock>::pop(const Packet* p)
{
    assert(!timers.empty());
    const auto& timer = timers.back();
    // timer.mark implies fastpath-related timeout
    bool timed_out = timer.marked;

    if ( timer.timed_out() )
    {
        Event e { p, timed_out, timers.back().elapsed() };

        if ( config->action & PacketLatencyConfig::LOG )
            log_handler.handle(e);

        if ( timed_out and (config->action & PacketLatencyConfig::ALERT) )
            event_handler.handle(e);
    }

    timers.pop_back();
    return timed_out;
}

template<typename Clock>
inline bool Impl<Clock>::fastpath()
{
    if ( !config->fastpath )
        return false;

    assert(!timers.empty());
    auto& timer = timers.back();
    if ( timer.timed_out() )
        timer.marked = true;

    return timer.marked;
}

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

static struct SnortConfigWrapper : ConfigWrapper
{
    const PacketLatencyConfig* operator->() const override
    { return &snort_conf->latency->packet_latency; }

} config;

static struct SnortEventHandler : EventHandler
{
    void handle(const Event&) override
    { SnortEventqAdd(GID_LATENCY, LATENCY_EVENT_PACKET_FASTPATHED); }
} event_handler;

static struct SnortLogHandler : EventHandler
{
    void handle(const Event& e) override
    {
        assert(e.packet);
        std::ostringstream ss;
        ss << e;
        LogMessage("%s\n", ss.str().c_str());
    }
} log_handler;

static THREAD_LOCAL Impl<>* impl = nullptr;

static inline Impl<>& get_impl()
{
    if ( !impl )
        impl = new Impl<>(config, event_handler, log_handler);

    return *impl;
}

} // namespace packet_latency

// -----------------------------------------------------------------------------
// packet latency interface
// -----------------------------------------------------------------------------

void PacketLatency::push()
{
    if ( packet_latency::config->enable )
    {
        packet_latency::get_impl().push();
        ++latency_stats.packets;
    }
}

void PacketLatency::pop(const Packet* p)
{
    if ( packet_latency::config->enable )
    {
        if ( packet_latency::get_impl().pop(p) )
            ++latency_stats.timeouts;
    }
}

bool PacketLatency::fastpath()
{
    if ( packet_latency::config->enable )
        return packet_latency::get_impl().fastpath();

    return false;
}

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#ifdef UNIT_TEST

namespace t_packet_latency
{

struct MockConfigWrapper : packet_latency::ConfigWrapper
{
    PacketLatencyConfig config;

    const PacketLatencyConfig* operator->() const override
    { return &config; }
};

struct EventHandlerSpy : packet_latency::EventHandler
{
    unsigned count = 0;
    void handle(const packet_latency::Event&) override
    { ++count; }
};

struct MockClock : ClockTraits<hr_clock>
{
    static hr_time t;

    static void reset()
    { t = hr_time(0_ticks); }

    static void inc(hr_duration d = 1_ticks)
    { t += d; }

    static hr_time now()
    { return t; }
};

hr_time MockClock::t = hr_time(0_ticks);

} // namespace t_packet_latency

TEST_CASE ( "packet latency impl", "[latency]" )
{
    // FIXIT-H J need to add checks for events

    using namespace t_packet_latency;

    MockConfigWrapper config;
    EventHandlerSpy event_handler;
    EventHandlerSpy log_handler;

    MockClock::reset();

    packet_latency::Impl<MockClock> impl(config, event_handler, log_handler);

    config.config.max_time = 2_ticks;
    config.config.action = PacketLatencyConfig::ALERT_AND_LOG;

    SECTION( "fastpath enabled" )
    {
        config.config.fastpath = true;

        // t = 0
        impl.push();

        SECTION( "timeout" )
        {
            MockClock::inc(config.config.max_time + 1_ticks);

            CHECK( impl.fastpath() );
            CHECK( impl.pop(nullptr) );

            CHECK( event_handler.count == 1 );
            CHECK( log_handler.count == 1 );
        }

        SECTION( "no timeout" )
        {
            CHECK_FALSE( impl.fastpath() );
            CHECK_FALSE( impl.pop(nullptr) );

            CHECK( event_handler.count == 0 );
            CHECK( log_handler.count == 0 );
        }
    }

    SECTION( "fastpath disabled" )
    {
        config.config.fastpath = false;

        // t = 0
        impl.push();

        SECTION( "timeout" )
        {
            MockClock::inc(config.config.max_time + 1_ticks);

            CHECK_FALSE( impl.fastpath() );
            CHECK_FALSE( impl.pop(nullptr) );

            CHECK( event_handler.count == 0 );
            CHECK( log_handler.count == 1 );
        }

        SECTION( "no timeout" )
        {
            CHECK_FALSE( impl.fastpath() );
            CHECK_FALSE( impl.pop(nullptr) );

            CHECK( event_handler.count == 0 );
            CHECK( log_handler.count == 0 );
        }
    }
}

#endif
