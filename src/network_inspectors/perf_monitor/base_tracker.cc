//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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

// base_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "base_tracker.h"  // FIXIT-W Returning null reference (from <vector>)

#include "managers/module_manager.h"
#include "main/thread.h"

#ifdef UNIT_TEST
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <thread>

#include "catch/snort_catch.h"
#include "utils/util.h"
#endif

using namespace snort;
using namespace std;

#ifdef UNIT_TEST
namespace
{
std::function<void()> summary_lock_attempt_hook;
}
#endif

BaseTracker::BaseTracker(PerfConfig* perf) : PerfTracker(perf, PERF_NAME "_base", PERF_BASE),
    modules(perf->modules), mods_to_prep(perf->mods_to_prep)
{
    is_first_packet_thread = (get_instance_id() == 0);
    global_proxies.resize(modules.size());

    for ( size_t mod_idx = 0; mod_idx < modules.size(); mod_idx++ )
    {
        ModuleConfig& mod = modules[mod_idx];
        if (mod.ptr->stats_are_aggregated())
            continue;

        formatter->register_section(mod.ptr->get_name());

        const bool is_global_stats = mod.ptr->global_stats();

        if ( is_global_stats )
        {
            const auto& snapshot = mod.global_stats_snapshot;
            if ( !snapshot.empty() && !mod.pegs.empty() )
            {
                global_proxies[mod_idx].mod = mod.ptr;
                global_proxies[mod_idx].enabled = true;
                global_proxies[mod_idx].values.assign(snapshot.size(), 0);
                global_proxies[mod_idx].last_seen = snapshot;
                has_global_proxies = true;

                for ( auto const& idx : mod.pegs )
                    formatter->register_field(mod.ptr->get_pegs()[idx].name, &(global_proxies[mod_idx].values[idx]));
            }
        }
        else
        {
            for ( auto const& idx : mod.pegs )
                formatter->register_field(mod.ptr->get_pegs()[idx].name, &(mod.ptr->get_counts()[idx]));
        }
    }
    formatter->finalize_fields();
}

void BaseTracker::update_global_proxies(bool summary)
{
    if ( !is_first_packet_thread || !has_global_proxies )
        return;

    // Periodic samples are best-effort and must not stall packet thread 0,
    // but the final summary must contain a coherent global counter snapshot.
    std::unique_lock<std::mutex> lock(ModuleManager::stats_mutex, std::defer_lock);
    if ( summary )
    {
#ifdef UNIT_TEST
        if ( summary_lock_attempt_hook )
            summary_lock_attempt_hook();
#endif
        lock.lock();
    }
    else
        lock.try_lock();

    if ( !lock.owns_lock() )
        return;

    for ( size_t mod_idx = 0; mod_idx < modules.size(); mod_idx++ )
    {
        GlobalProxy& proxy = global_proxies[mod_idx];
        if ( proxy.enabled && proxy.mod )
            proxy.mod->prep_counts(false);
    }

    for ( size_t mod_idx = 0; mod_idx < modules.size(); mod_idx++ )
    {
        GlobalProxy& proxy = global_proxies[mod_idx];
        if ( !proxy.enabled || !proxy.mod )
            continue;

        const Module* mod = proxy.mod;
        const PegCount* p = mod->get_counts();
        const PegInfo* pegs = mod->get_pegs();
        if ( !p || !pegs )
            continue;

        for ( const auto& peg_idx : modules[mod_idx].pegs )
        {
            const PegCount cur = p[peg_idx];

            if ( pegs[peg_idx].type == CountType::SUM )
            {
                const PegCount prev = proxy.last_seen[peg_idx];
                proxy.values[peg_idx] = (cur >= prev) ? (cur - prev) : cur;
                proxy.last_seen[peg_idx] = cur;
            }
            else
            {
                proxy.values[peg_idx] = cur;
            }
        }
    }
}

void BaseTracker::process(bool summary)
{
    for ( Module* mod : mods_to_prep )
    {
        if ( !mod || mod->global_stats() )
            continue;

        mod->prep_counts(false);
    }

    update_global_proxies(summary);

    write();

    if ( !summary )
    {
        for ( const ModuleConfig& mod : modules )
        {
            if (mod.ptr->is_aggregator())
                continue;

            if ( mod.ptr->global_stats() )
                continue;

            mod.ptr->sum_stats(false);
        }
    }
}

#ifdef UNIT_TEST

class MockModule : public Module
{
public:
    MockModule(bool global_stats = false) : Module("mockery", "mockery"),
        global_stats_enabled(global_stats)
    {
        mock_counts = (PegCount*)snort_alloc(5 * sizeof(PegCount));

        for( unsigned i = 0; i < 5; i++ )
            mock_counts[i] = i;
    }

    ~MockModule() override { snort_free(mock_counts); }

    const PegInfo* get_pegs() const override { return pegs; }

    PegCount* get_counts() const override { return mock_counts; }

    bool global_stats() const override { return global_stats_enabled; }

    void prep_counts(bool) override { ++prep_count; }

    void sum_stats(bool) override {}

    void init_stats(bool) override {Module::init_stats();}

    void real_sum_stats() { Module::sum_stats(false); }

    void increment_counts()
    {
        for ( unsigned i = 0; i < 5; ++i )
            ++mock_counts[i];
    }

    Usage get_usage() const override
    { return INSPECT; }

    unsigned get_prep_count() const { return prep_count; }

private:
    PegCount* mock_counts;
    bool global_stats_enabled;
    unsigned prep_count = 0;

    PegInfo pegs[6] =
    {
        { CountType::SUM, "zero", ""},
        { CountType::SUM, "one", ""},
        { CountType::SUM, "two", ""},
        { CountType::SUM, "three", ""},
        { CountType::SUM, "four", ""},
        { CountType::END, nullptr, nullptr }
    };
};

class MockBaseTracker : public BaseTracker
{
public:
    PerfFormatter* output;

    MockBaseTracker(PerfConfig* config) : BaseTracker(config)
    { output = formatter; }
};

TEST_CASE("module stats", "[BaseTracker]")
{
    unsigned pass = 0;
    PegCount expected[2][5] = {
        {0, 2, 4},
        {0, 0, 0}};

    PerfConfig config;
    config.format = PerfFormat::MOCK;

    MockModule mod;
    mod.init_stats(false);
    ModuleConfig mod_cfg;
    mod_cfg.ptr = &mod;
    mod_cfg.pegs = {0, 2, 4};
    config.modules.emplace_back(mod_cfg);

    MockBaseTracker tracker(&config);
    MockFormatter *formatter = reinterpret_cast<MockFormatter*>(tracker.output);

    tracker.reset();
    tracker.process(false);
    CHECK(*formatter->public_values["mockery.zero"].pc == expected[pass][0]);
    CHECK(*formatter->public_values["mockery.two"].pc == expected[pass][1]);
    CHECK(*formatter->public_values["mockery.four"].pc == expected[pass++][2]);
    mod.real_sum_stats();

    tracker.process(false);
    CHECK(*formatter->public_values["mockery.zero"].pc == expected[pass][0]);
    CHECK(*formatter->public_values["mockery.two"].pc == expected[pass][1]);
    CHECK(*formatter->public_values["mockery.four"].pc == expected[pass++][2]);
    mod.real_sum_stats();
}

TEST_CASE("global module stats", "[BaseTracker]")
{
    PerfConfig config;
    config.format = PerfFormat::MOCK;

    MockModule mod(true);
    mod.init_stats(false);
    ModuleConfig mod_cfg;
    mod_cfg.ptr = &mod;
    mod_cfg.pegs = {0, 2, 4};
    mod_cfg.global_stats_snapshot.assign(mod.get_counts(), mod.get_counts() + mod.get_num_counts());
    config.modules.emplace_back(mod_cfg);

    // The snapshot predates tracker construction, while live global counters continue advancing.
    mod.increment_counts();

    MockBaseTracker tracker(&config);
    MockFormatter* formatter = reinterpret_cast<MockFormatter*>(tracker.output);

    tracker.reset();
    tracker.process(false);
    CHECK(*formatter->public_values["mockery.zero"].pc == 1);
    CHECK(*formatter->public_values["mockery.two"].pc == 1);
    CHECK(*formatter->public_values["mockery.four"].pc == 1);
}

TEST_CASE("summary with global proxies waits for and writes fresh stats", "[BaseTracker]")
{
    PerfConfig config;
    config.format = PerfFormat::MOCK;

    MockModule mod(true);
    mod.init_stats(false);
    ModuleConfig mod_cfg;
    mod_cfg.ptr = &mod;
    mod_cfg.pegs = {0, 2, 4};
    mod_cfg.global_stats_snapshot.assign(mod.get_counts(), mod.get_counts() + mod.get_num_counts());
    config.modules.emplace_back(mod_cfg);

    MockBaseTracker tracker(&config);
    MockFormatter* formatter = reinterpret_cast<MockFormatter*>(tracker.output);

    std::unique_lock<std::mutex> lock(ModuleManager::stats_mutex);
    std::promise<void> lock_attempted;
    std::future<void> worker_at_lock = lock_attempted.get_future();
    std::promise<void> allow_lock_attempt;
    std::shared_future<void> may_attempt_lock = allow_lock_attempt.get_future().share();
    std::promise<void> done;
    std::future<void> worker_done = done.get_future();
    summary_lock_attempt_hook = [&lock_attempted, may_attempt_lock]()
    {
        lock_attempted.set_value();
        may_attempt_lock.wait();
    };
    std::thread worker([&tracker, &done]()
    {
        tracker.process(true);
        done.set_value();
    });

    const std::future_status reached_lock = worker_at_lock.wait_for(std::chrono::seconds(2));
    allow_lock_attempt.set_value();
    const std::future_status blocked = worker_done.wait_for(std::chrono::seconds(1));
    mod.increment_counts();
    lock.unlock();
    const std::future_status completed = worker_done.wait_for(std::chrono::seconds(2));
    worker.join();
    summary_lock_attempt_hook = {};

    REQUIRE(reached_lock == std::future_status::ready);
    CHECK(blocked == std::future_status::timeout);
    REQUIRE(completed == std::future_status::ready);
    CHECK(*formatter->public_values["mockery.zero"].pc == 1);
    CHECK(*formatter->public_values["mockery.two"].pc == 1);
    CHECK(*formatter->public_values["mockery.four"].pc == 1);
}

TEST_CASE("summary without global proxies does not wait for stats mutex", "[BaseTracker]")
{
    PerfConfig config;
    config.format = PerfFormat::MOCK;

    MockModule mod;
    mod.init_stats(false);
    ModuleConfig mod_cfg;
    mod_cfg.ptr = &mod;
    mod_cfg.pegs = {0};
    config.modules.emplace_back(mod_cfg);

    MockBaseTracker tracker(&config);

    std::unique_lock<std::mutex> lock(ModuleManager::stats_mutex);
    std::promise<void> started;
    std::future<void> worker_started = started.get_future();
    std::promise<void> done;
    std::future<void> worker_done = done.get_future();
    std::thread worker([&tracker, &started, &done]()
    {
        started.set_value();
        tracker.process(true);
        done.set_value();
    });

    worker_started.wait();
    const std::future_status status = worker_done.wait_for(std::chrono::seconds(2));
    lock.unlock();
    worker.join();

    CHECK(status == std::future_status::ready);
}

TEST_CASE("summary with no selected global pegs skips stats mutex and refresh", "[BaseTracker]")
{
    PerfConfig config;
    config.format = PerfFormat::MOCK;

    MockModule mod(true);
    mod.init_stats(false);
    ModuleConfig mod_cfg;
    mod_cfg.ptr = &mod;
    mod_cfg.global_stats_snapshot.assign(mod.get_counts(), mod.get_counts() + mod.get_num_counts());
    REQUIRE(!mod_cfg.global_stats_snapshot.empty());
    REQUIRE(mod_cfg.pegs.empty());
    config.modules.emplace_back(mod_cfg);

    MockBaseTracker tracker(&config);
    MockFormatter* formatter = reinterpret_cast<MockFormatter*>(tracker.output);
    std::atomic<unsigned> lock_attempts = 0;
    summary_lock_attempt_hook = [&lock_attempts]() { ++lock_attempts; };

    std::unique_lock<std::mutex> lock(ModuleManager::stats_mutex);
    std::promise<void> done;
    std::future<void> worker_done = done.get_future();
    std::thread worker([&tracker, &done]()
    {
        tracker.process(true);
        done.set_value();
    });

    const std::future_status completed = worker_done.wait_for(std::chrono::seconds(2));
    lock.unlock();
    worker.join();
    summary_lock_attempt_hook = {};

    REQUIRE(completed == std::future_status::ready);
    CHECK(lock_attempts.load() == 0);
    CHECK(mod.get_prep_count() == 0);
    CHECK(formatter->public_values.empty());
}
#endif
