//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// rule_latency.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rule_latency.h"

#include "detection/detection_engine.h"
#include "detection/detection_options.h"
#include "detection/treenodes.h"
#include "main/snort_config.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "utils/stats.h"

#include "latency_config.h"
#include "latency_rules.h"
#include "latency_stats.h"
#include "latency_timer.h"
#include "latency_util.h"
#include "rule_latency_state.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#include "main/thread_config.h"
#endif

using namespace snort;

namespace rule_latency
{
// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

struct Event
{
    enum Type
    {
        EVENT_ENABLED,
        EVENT_TIMED_OUT,
        EVENT_SUSPENDED
    };

    Type type;
    typename SnortClock::duration elapsed;
    detection_option_tree_root_t* root;
    Packet* packet;
};

template<typename Clock>
class RuleTimer : public LatencyTimer<Clock>
{
public:
    RuleTimer(typename Clock::duration d, detection_option_tree_root_t* root, Packet* p) :
        LatencyTimer<Clock>(d), root(root), packet(p) { }

    detection_option_tree_root_t* root;
    Packet* packet;
};

using ConfigWrapper = ReferenceWrapper<RuleLatencyConfig>;
using EventHandler = EventingWrapper<Event>;

static inline std::ostream& operator<<(std::ostream& os, const Event& e)
{
    using std::chrono::duration_cast;
    using std::chrono::microseconds;

    os << "latency: " << e.packet->context->packet_number << " rule tree ";

    switch ( e.type )
    {
    case Event::EVENT_ENABLED:
        os << "enabled: ";
        break;

    case Event::EVENT_TIMED_OUT:
        os << "timed out: ";
        break;

    case Event::EVENT_SUSPENDED:
        os << "suspended: ";
        break;
    }

    os << clock_usecs(TO_USECS(e.elapsed)) << " usec, ";
    os << e.root->otn->sigInfo.gid << ":" << e.root->otn->sigInfo.sid << ":"
        << e.root->otn->sigInfo.rev;

    if ( e.root->num_children > 1 )
        os << " (of " << e.root->num_children << ")";

    os << ", " << e.packet->ptrs.ip_api.get_src() << ":" << e.packet->ptrs.sp;
    os << " -> " << e.packet->ptrs.ip_api.get_dst() << ":" << e.packet->ptrs.dp;

    return os;
}

// -----------------------------------------------------------------------------
// rule tree interface
// -----------------------------------------------------------------------------

// goes in a static structure so we can templatize Impl
struct DefaultRuleInterface
{
    static bool is_suspended(const detection_option_tree_root_t& root)
    { return root.latency_state[get_instance_id()].suspended; }

    // return true if rule was *reenabled*
    template<typename Duration, typename Time>
    static bool reenable(detection_option_tree_root_t& root, Duration max_suspend_time,
        Time cur_time)
    {
        auto& state = root.latency_state[get_instance_id()];
        if ( state.suspended && (cur_time - state.suspend_time > max_suspend_time) )
        {
            state.enable();
            return true;
        }

        return false;
    }

    template<typename Time>
    static bool timeout_and_suspend(detection_option_tree_root_t& root, unsigned threshold,
        Time time, bool do_suspend)
    {
        auto& state = root.latency_state[get_instance_id()];

        ++state.timeouts;

        // the separate loops in each branch are so we can avoid iterating
        // over the children twice in the suspend case

        if ( do_suspend and state.timeouts >= threshold )
        {
            state.suspend(time);

            for ( int i = 0; i < root.num_children; ++i )
            {
                auto& child_state = root.children[i]->state[get_instance_id()];
                // FIXIT-L rename to something like latency_timeout_count
                ++child_state.latency_timeouts;
                ++child_state.latency_suspends;
            }

            return true;
        }

        else
        {
            for ( int i = 0; i < root.num_children; ++i )
            {
                // FIXIT-L rename to something like latency_timeout_count
                ++root.children[i]->state[get_instance_id()].latency_timeouts;
            }
        }

        return false;
    }
};

// -----------------------------------------------------------------------------
// implementation
// -----------------------------------------------------------------------------

template<typename Clock = SnortClock, typename RuleTree = DefaultRuleInterface>
class Impl
{
public:
    Impl(const ConfigWrapper&, EventHandler&, EventHandler&);

    bool push(detection_option_tree_root_t*, Packet*);
    bool pop();
    bool suspended() const;

private:
    void handle(const Event&);

    std::vector<RuleTimer<Clock>> timers;
    const ConfigWrapper& config;
    EventHandler& event_handler;
    EventHandler& log_handler;
};

template<typename Clock, typename RuleTree>
inline Impl<Clock, RuleTree>::Impl(const ConfigWrapper& cfg, EventHandler& eh, EventHandler& lh) :
    config(cfg), event_handler(eh), log_handler(lh)
{ }

template<typename Clock, typename RuleTree>
inline bool Impl<Clock, RuleTree>::push(detection_option_tree_root_t* root, Packet* p)
{
    assert(root and p);

    // FIXIT-L rule timer is pushed even if rule is not enabled (no visible side-effects)
    timers.emplace_back(config->max_time, root, p);

    if ( config->allow_reenable() )
    {
        if ( RuleTree::reenable(*root, config->max_suspend_time, Clock::now()) )
        {
            Event e { Event::EVENT_ENABLED, config->max_suspend_time, root, p };
            handle(e);
            return true;
        }
    }

    return false;
}

template<typename Clock, typename RuleTree>
inline bool Impl<Clock, RuleTree>::pop()
{
    assert(!timers.empty());
    const auto& timer = timers.back();

    bool timed_out = false;

    if ( !RuleTree::is_suspended(*timer.root) )
    {
        timed_out = timer.timed_out();

        if ( timed_out )
        {
            auto suspended = RuleTree::timeout_and_suspend(*timer.root, config->suspend_threshold,
                Clock::now(), config->suspend);

            Event e
            {
                suspended ? Event::EVENT_SUSPENDED : Event::EVENT_TIMED_OUT,
                timer.elapsed(), timer.root, timer.packet
            };

            handle(e);
        }
    }

    timers.pop_back();
    return timed_out;
}

template<typename Clock, typename RuleTree>
inline bool Impl<Clock, RuleTree>::suspended() const
{
    if ( !config->suspend )
        return false;

    assert(!timers.empty());
    return RuleTree::is_suspended(*timers.back().root);
}

template<typename Clock, typename RuleTree>
inline void Impl<Clock, RuleTree>::handle(const Event& e)
{
    if ( config->action & RuleLatencyConfig::LOG )
        log_handler.handle(e);

    if ( config->action & RuleLatencyConfig::ALERT )
        event_handler.handle(e);
}

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

static struct SnortConfigWrapper : public ConfigWrapper
{
    const RuleLatencyConfig* operator->() const override
    { return &SnortConfig::get_conf()->latency->rule_latency; }

} config;

static struct SnortEventHandler : public EventHandler
{
    void handle(const Event& e) override
    {
        switch ( e.type )
        {
            case Event::EVENT_ENABLED:
                DetectionEngine::queue_event(GID_LATENCY, LATENCY_EVENT_RULE_TREE_ENABLED);
                break;

            case Event::EVENT_SUSPENDED:
                DetectionEngine::queue_event(GID_LATENCY, LATENCY_EVENT_RULE_TREE_SUSPENDED);
                break;

            default:
                break;
        }
    }
} event_handler;

static struct SnortLogHandler : public EventHandler
{
    void handle(const Event& e) override
    {
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

} // namespace rule_latency

// -----------------------------------------------------------------------------
// rule latency interface
// -----------------------------------------------------------------------------

void RuleLatency::push(detection_option_tree_root_t* root, Packet* p)
{
    if ( rule_latency::config->enabled() )
    {
        if ( rule_latency::get_impl().push(root, p) )
            ++latency_stats.rule_tree_enables;

        ++latency_stats.total_rule_evals;
    }
}

void RuleLatency::pop()
{
    if ( rule_latency::config->enabled() )
    {
        if ( rule_latency::get_impl().pop() )
            ++latency_stats.rule_eval_timeouts;
    }
}

bool RuleLatency::suspended()
{
    if ( rule_latency::config->enabled() )
        return rule_latency::get_impl().suspended();

    return false;
}

void RuleLatency::tterm()
{
    using rule_latency::impl;

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

namespace t_rule_latency
{

struct MockConfigWrapper : public rule_latency::ConfigWrapper
{
    RuleLatencyConfig config;

    const RuleLatencyConfig* operator->() const override
    { return &config; }
};

struct EventHandlerSpy : public rule_latency::EventHandler
{
    unsigned count = 0;
    void handle(const rule_latency::Event&) override
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

struct RuleInterfaceSpy
{
    static bool is_suspended_result;
    static bool is_suspended_called;
    static bool reenable_result;
    static bool reenable_called;
    static bool timeout_and_suspend_result;
    static bool timeout_and_suspend_called;

    static void reset()
    {
        is_suspended_result = false;
        is_suspended_called = false;
        reenable_result = false;
        reenable_called = false;
        timeout_and_suspend_result = false;
        timeout_and_suspend_called = false;
    }

    static bool is_suspended(const detection_option_tree_root_t&)
    { is_suspended_called = true; return is_suspended_result; }

    template<typename Duration, typename Time>
    static bool reenable(detection_option_tree_root_t&, Duration, Time)
    { reenable_called = true; return reenable_result; }

    template<typename Time>
    static bool timeout_and_suspend(detection_option_tree_root_t&, unsigned, Time, bool)
    { timeout_and_suspend_called = true; return timeout_and_suspend_result; }
};

bool RuleInterfaceSpy::is_suspended_result = false;
bool RuleInterfaceSpy::is_suspended_called = false;
bool RuleInterfaceSpy::reenable_result = false;
bool RuleInterfaceSpy::reenable_called = false;
bool RuleInterfaceSpy::timeout_and_suspend_result = false;
bool RuleInterfaceSpy::timeout_and_suspend_called = false;

} // namespace t_rule_latency

TEST_CASE ( "rule latency impl", "[latency]" )
{
    using namespace t_rule_latency;

    MockConfigWrapper config;
    EventHandlerSpy event_handler;
    EventHandlerSpy log_handler;

    MockClock::reset();
    RuleInterfaceSpy::reset();

    config.config.action = RuleLatencyConfig::ALERT_AND_LOG;

    detection_option_tree_root_t root;
    Packet pkt(false);

    rule_latency::Impl<MockClock, RuleInterfaceSpy> impl(config, event_handler, log_handler);

    SECTION( "push" )
    {
        SECTION( "reenable allowed" )
        {
            config.config.max_suspend_time = 1_ticks;

            SECTION( "push rule" )
            {
                CHECK_FALSE( impl.push(&root, &pkt) );
                CHECK( log_handler.count == 0 );
                CHECK( event_handler.count == 0 );
                CHECK( RuleInterfaceSpy::reenable_called );
            }

            SECTION( "push rule -- reenabled" )
            {
                RuleInterfaceSpy::reenable_result = true;

                CHECK( impl.push(&root, &pkt) );
                CHECK( log_handler.count == 1 );
                CHECK( event_handler.count == 1 );
                CHECK( RuleInterfaceSpy::reenable_called );
            }
        }

        SECTION( "reenable not allowed" )
        {
            config.config.max_suspend_time = 0_ticks;

            SECTION( "push rule" )
            {
                CHECK_FALSE( impl.push(&root, &pkt) );
                CHECK( log_handler.count == 0 );
                CHECK( event_handler.count == 0 );
                CHECK_FALSE( RuleInterfaceSpy::reenable_called );
            }
        }
    }

    SECTION( "enabled" )
    {
        RuleInterfaceSpy::is_suspended_result = true;

        impl.push(&root, &pkt);

        SECTION( "suspending of rules disabled" )
        {
            config.config.suspend = false;

            CHECK_FALSE( impl.suspended() );
            CHECK_FALSE( RuleInterfaceSpy::is_suspended_called );
        }

        SECTION( "suspend of rules enabled" )
        {
            config.config.suspend = true;

            CHECK( impl.suspended() );
            CHECK( RuleInterfaceSpy::is_suspended_called );
        }
    }

    SECTION( "pop" )
    {
        config.config.max_time = 1_ticks;

        impl.push(&root, &pkt);

        SECTION( "rule timeout" )
        {
            MockClock::inc(2_ticks);

            SECTION( "rule already suspended" )
            {
                RuleInterfaceSpy::is_suspended_result = true;

                CHECK_FALSE( impl.pop() );
                CHECK( log_handler.count == 0 );
                CHECK( event_handler.count == 0 );
                CHECK_FALSE( RuleInterfaceSpy::timeout_and_suspend_called );
            }

            SECTION( "rule suspended" )
            {
                RuleInterfaceSpy::is_suspended_result = false;
                RuleInterfaceSpy::timeout_and_suspend_result = true;

                CHECK( impl.pop() );
                CHECK( log_handler.count == 1 );
                CHECK( event_handler.count == 1 );
                CHECK( RuleInterfaceSpy::timeout_and_suspend_called );
            }

            SECTION( "rule not suspended" )
            {
                RuleInterfaceSpy::timeout_and_suspend_result = false;

                CHECK( impl.pop() );
                CHECK( log_handler.count == 1 );
                CHECK( event_handler.count == 1 );
                CHECK( RuleInterfaceSpy::timeout_and_suspend_called );
            }

            CHECK( RuleInterfaceSpy::is_suspended_called );
        }

        SECTION( "no rule timeout" )
        {
            RuleInterfaceSpy::is_suspended_result = false;

            CHECK_FALSE( impl.pop() );
            CHECK( log_handler.count == 0 );
            CHECK( event_handler.count == 0 );
            CHECK_FALSE( RuleInterfaceSpy::timeout_and_suspend_called );
        }
    }
}

TEST_CASE ( "default latency rule interface", "[latency]" )
{
    using RuleInterface = rule_latency::DefaultRuleInterface;

    // construct a mock rule tree

    auto instances = ThreadConfig::get_instance_max();
    if ( !instances )
        instances = 1;

    std::unique_ptr<RuleLatencyState[]> latency_state(new RuleLatencyState[instances]());

    std::unique_ptr<detection_option_tree_node_t*[]> children(
        new detection_option_tree_node_t*[1]());

    detection_option_tree_node_t child;
    children[0] = &child;

    std::unique_ptr<dot_node_state_t[]> child_state(new dot_node_state_t[instances]());
    child.state = child_state.get();

    detection_option_tree_root_t root;
    root.latency_state = latency_state.get();
    root.num_children = 1;
    root.children = children.get();

    SECTION( "is_suspended" )
    {
        CHECK_FALSE( RuleInterface::is_suspended(root) );
        root.latency_state[0].suspend(hr_time(0_ticks));
        CHECK( RuleInterface::is_suspended(root) );
    }

    SECTION( "reenable" )
    {
        SECTION( "rule already enabled" )
        {
            REQUIRE_FALSE( root.latency_state[get_instance_id()].suspended );
            CHECK_FALSE( RuleInterface::reenable(root, 0_ticks, hr_time(0_ticks)) );
        }

        SECTION( "rule suspended" )
        {
            root.latency_state[get_instance_id()].suspend(hr_time(0_ticks));

            SECTION( "suspend time not exceeded" )
            {
                CHECK_FALSE( RuleInterface::reenable(root, 1_ticks, hr_time(0_ticks)) );
            }

            SECTION( "suspend time exceeded" )
            {
                CHECK( RuleInterface::reenable(root, 1_ticks, hr_time(2_ticks)) );
            }
        }
    }

    SECTION( "timeout_and_suspend" )
    {
        SECTION( "suspend enabled" )
        {
            SECTION( "timeouts under threshold" )
            {
                CHECK_FALSE( RuleInterface::timeout_and_suspend(root, 2, hr_time(0_ticks), true) );
                CHECK( child_state[0].latency_timeouts == 1 );
                CHECK( child_state[0].latency_suspends == 0 );
            }

            SECTION( "timeouts exceed threshold" )
            {
                CHECK( RuleInterface::timeout_and_suspend(root, 1, hr_time(0_ticks), true) );
                CHECK( child_state[0].latency_timeouts == 1 );
                CHECK( child_state[0].latency_suspends == 1 );
            }
        }

        SECTION( "suspend disabled" )
        {
            CHECK_FALSE( RuleInterface::timeout_and_suspend(root, 0, hr_time(0_ticks), false) );
            CHECK( child_state[0].latency_timeouts == 1 );
            CHECK( child_state[0].latency_suspends == 0 );
        }
    }
}

#endif
