//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_latency.h"

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "trace/trace_api.h"
#include "utils/stats.h"

#include "latency_config.h"
#include "latency_rules.h"
#include "latency_stats.h"
#include "latency_timer.h"
#include "latency_util.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

static THREAD_LOCAL uint64_t elapsed = 0;

namespace packet_latency
{
// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

struct Event
{
    const Packet* packet;
    bool fastpathed;
    typename SnortClock::duration elapsed;
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

static inline std::ostream& operator<<(std::ostream& os, const Event& e)
{
    os << "packet " << e.packet->context->packet_number;

    if ( e.fastpathed )
        os << " fastpathed: ";
    else
        os << " timed out: ";

    os << clock_usecs(TO_USECS(e.elapsed)) << " usec, ";

    if ( e.packet->is_cooked() )
        os << e.packet->get_pseudo_type();
    else
        os << e.packet->get_type();

    os << "[" << e.packet->dsize << "]";

    if ( e.packet->has_ip() or e.packet->is_data() )
    {
        SfIpString src_addr, dst_addr;
        unsigned src_port = 0, dst_port = 0;

        e.packet->ptrs.ip_api.get_src()->ntop(src_addr);
        e.packet->ptrs.ip_api.get_dst()->ntop(dst_addr);
        if ( e.packet->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        {
            src_port = e.packet->ptrs.sp;
            dst_port = e.packet->ptrs.dp;
        }

        os << ", " << src_addr << ":" << src_port;
        os << " -> " << dst_addr << ":" << dst_port;
    }

    return os;
}

// -----------------------------------------------------------------------------
// implementation
// -----------------------------------------------------------------------------

template<typename Clock = SnortClock>
class Impl
{
public:
    Impl(const ConfigWrapper&, EventHandler&);

    void push();
    bool pop(const Packet*);
    bool fastpath();

private:
    // FIXIT-L use custom struct instead of std::pair for better semantics
    // std::vector<std::pair<LatencyTimer<Clock>, bool>> contexts;
    std::vector<PacketTimer<Clock>> timers;
    const ConfigWrapper& config;
    EventHandler& event_handler;
};

template<typename Clock>
inline Impl<Clock>::Impl(const ConfigWrapper& cfg, EventHandler& eh) :
    config(cfg), event_handler(eh)
{ }

template<typename Clock>
inline void Impl<Clock>::push()
{
    timers.emplace_back(config->max_time);
}

template<typename Clock>
inline bool Impl<Clock>::pop(const Packet* p)
{
    assert(!timers.empty());
    const auto& timer = timers.back();

    auto timed_out = timer.marked_as_fastpathed;

    bool force_timeout = timer.timed_out();

#ifdef REG_TEST
    force_timeout = config->test_timeout ? true : force_timeout;
#endif

    if ( force_timeout )
    {
        timed_out = true;

        // timer.mark implies fastpath-related timeout
        Event e { p, timer.marked_as_fastpathed, timer.elapsed() };

        event_handler.handle(e);
    }

    elapsed = clock_usecs(TO_USECS(timer.elapsed()));

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
    { return &SnortConfig::get_conf()->latency->packet_latency; }

} config;

static struct SnortEventHandler : public EventHandler
{
    void handle(const Event& e) override
    {
        assert(e.packet);
        std::ostringstream ss;
        ss << e;
        debug_logf(latency_trace, e.packet, "%s\n", ss.str().c_str());

        DetectionEngine::queue_event(GID_LATENCY, LATENCY_EVENT_PACKET_FASTPATHED);
    }
} event_handler;

static THREAD_LOCAL Impl<>* impl = nullptr;

// FIXIT-L this should probably be put in a tinit
static inline Impl<>& get_impl()
{
    if ( !impl )
        impl = new Impl<>(config, event_handler);

    return *impl;
}

} // namespace packet_latency

// -----------------------------------------------------------------------------
// packet latency interface
// -----------------------------------------------------------------------------

void PacketLatency::push()
{
    if ( packet_latency::config->force_enabled())
    {
        packet_latency::get_impl().push();
        ++latency_stats.total_packets;
    }
}

void PacketLatency::pop(const Packet* p)
{
    if ( packet_latency::config->force_enabled())
    {
        if ( packet_latency::get_impl().pop(p) )
            ++latency_stats.packet_timeouts;

        // FIXIT-L the timer is still running so this max is slightly larger than logged
        if ( elapsed > latency_stats.max_usecs )
            latency_stats.max_usecs = elapsed;

        if ( p->flow )
            p->flow->flowstats.total_flow_latency += elapsed;

        latency_stats.total_usecs += elapsed;
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

    MockClock::reset();

    packet_latency::Impl<MockClock> impl(config, event_handler);

    config.config.max_time = 2_ticks;
    SECTION( "fastpath enabled" )
    {
        config.config.fastpath = true;

        // t = 0
        impl.push();

        SECTION( "timeout" )
        {
            MockClock::inc(config.config.max_time + 1_ticks);

            CHECK( true == impl.fastpath() );
            CHECK( true == impl.pop(nullptr) );

            CHECK( event_handler.count == 1 );
        }

        SECTION( "no timeout" )
        {
            CHECK( false == impl.fastpath() );
            CHECK( false == impl.pop(nullptr) );

            CHECK( event_handler.count == 0 );
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

            CHECK( false == impl.fastpath() );
            CHECK( true == impl.pop(nullptr) );

            CHECK( event_handler.count == 1 );
        }

        SECTION( "no timeout" )
        {
            CHECK( false == impl.fastpath() );
            CHECK( false == impl.pop(nullptr) );

            CHECK( event_handler.count == 0 );
        }
    }
}

#endif
