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

template<typename Clock>
class PacketTimer : public LatencyTimer<Clock>
{
public:
    PacketTimer(typename Clock::duration d) :
        LatencyTimer<Clock>(d) { }

    bool marked_as_fastpathed = false;
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
        os << " (fastpathed)";

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
    // FIXIT-L use custom struct instead of std::pair for better semantics
    // std::vector<std::pair<LatencyTimer<Clock>, bool>> contexts;
    std::vector<PacketTimer<Clock>> timers;
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
    auto max_time = duration_cast<typename Clock::duration>(config->max_time);
    timers.emplace_back(max_time);
}

template<typename Clock>
inline bool Impl<Clock>::pop(const Packet* p)
{
    assert(!timers.empty());
    const auto& timer = timers.back();

    auto timed_out = timer.marked_as_fastpathed;

    if ( timer.timed_out() )
    {
        timed_out = true;

        // timer.mark implies fastpath-related timeout
        Event e { p, timer.marked_as_fastpathed, timer.elapsed() };

        if ( config->action & PacketLatencyConfig::LOG )
            log_handler.handle(e);

        if ( timer.marked_as_fastpathed and (config->action & PacketLatencyConfig::ALERT) )
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

    if ( !timer.marked_as_fastpathed )
    {
        if ( timer.timed_out() )
            timer.marked_as_fastpathed = true;
    }

    return timer.marked_as_fastpathed;
}

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

static struct SnortConfigWrapper : public ConfigWrapper
{
    const PacketLatencyConfig* operator->() const override
    { return &snort_conf->latency->packet_latency; }

} config;

static struct SnortEventHandler : public EventHandler
{
    void handle(const Event&) override
    { SnortEventqAdd(GID_LATENCY, LATENCY_EVENT_PACKET_FASTPATHED); }
} event_handler;

static struct SnortLogHandler : public EventHandler
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
    if ( packet_latency::config->enabled() )
    {
        packet_latency::get_impl().push();
        ++latency_stats.total_packets;
    }
}

void PacketLatency::pop(const Packet* p)
{
    if ( packet_latency::config->enabled() )
    {
        if ( packet_latency::get_impl().pop(p) )
            ++latency_stats.packet_timeouts;
    }
}

bool PacketLatency::fastpath()
{
    if ( packet_latency::config->enabled() )
        return packet_latency::get_impl().fastpath();

    return false;
}

void PacketLatency::tterm()
{
    using packet_latency::impl;

    if ( impl )
    {
        delete impl;
        impl = nullptr;
    }
}

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#ifdef UNIT_TEST

namespace t_packet_latency
{

struct MockConfigWrapper : public packet_latency::ConfigWrapper
{
    PacketLatencyConfig config;

    const PacketLatencyConfig* operator->() const override
    { return &config; }
};

struct EventHandlerSpy : public packet_latency::EventHandler
{
    unsigned count = 0;
    void handle(const packet_latency::Event&) override
    { ++count; }
};

struct MockClock : public ClockTraits<hr_clock>
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
    // FIXIT-L need to add checks for events

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
            CHECK( impl.pop(nullptr) );

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
