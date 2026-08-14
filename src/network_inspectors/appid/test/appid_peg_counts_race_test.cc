//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

// appid_peg_counts_race_test.cc author Steve Chew <stechew@cisco.com>
//
// Regression tests for a data race on the AppId peg counts.
// PR #4253 (2024-03-26) removed the std::shared_mutex (appid_peg_ids_mutex)
// that PR #4132 (2024-01-16) had added to guard the shared appid_peg_ids map
// and the appid_dynamic_sum aggregation. Two races result:
//
//   1) concurrent_add_vs_sum_stats  (the field crash)
//      add_app_peg_info() emplace()  (detector/ODP reload, control thread)
//      vs init_pegs()/sum_stats()    (packet-thread tinit/tterm) reading the
//      SAME appid_peg_ids map object -> rehash under a reader -> corrupt node.
//
//   2) concurrent_print_vs_writers  (residual race found during review)
//      print()/show_dynamic_stats() (control thread) reads *appid_peg_ids AND
//      appid_dynamic_sum with no lock, racing add_app_peg_info() (map) and
//      sum_stats() (appid_dynamic_sum).
//
// HOW TO BUILD/RUN:
//   cmake ... -DENABLE_UNIT_TESTS=ON        (no sanitizer required)
//   then run the appid_peg_counts_race_test binary.
//
// Detection does NOT depend on a sanitizer. Without the lock, a concurrent
// emplace()/rehash corrupts the shared map while a reader walks it, so the
// peg_ids->at() in sum_stats() either throws std::out_of_range or dereferences
// a corrupt node -- both fail the test deterministically in a plain build.
// Adding a sanitizer only sharpens the diagnosis: TSAN names both racing
// accesses with stacks, and ASAN reports the bad access directly.
//
// The regression window is the period during which the writer is still adding
// NEW ids (each insertion may rehash) while a reader walks the same map. That
// window is finite, so the test coordinates the threads to guarantee it opens:
// a start barrier holds the writer until every reader has snapshotted the map
// and entered its read loop, and the writer then adds new ids for exactly as
// long as a reader is still running. The test asserts that the overlap actually
// happened, so a run that fails to interleave is reported as an inconclusive
// FAILURE rather than passing silently.
//
// LIMITATION: catching the regression needs genuine parallelism -- a reader has to
// be inside the peg_ids->at() bucket walk at the moment the writer rehashes it. On
// a single CPU that would require preemption inside a sub-microsecond lookup, and
// the unfixed code is NOT reliably caught there (measured: 0/8 runs detected when
// pinned to one core, versus 8/8 on two cores, 8/8 under heavy background load, and
// 10/10 under ASAN and TSAN). CI runners are multi-core, so this is documented
// rather than worked around -- widening the window would mean instrumenting the
// production path, which would be worse.
//
// EXPECTED:
//   * Without the fix: fails in plain, ASAN and TSAN builds (verified on
//     Linux/gcc and FreeBSD/libc++), in both test cases independently.
//   * With the fix (reader/writer lock restored on appid_peg_ids in
//     add/init/sum, plus a print() guard, all in appid_peg_ids -> dynamic_stats
//     lock order): clean.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <atomic>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "network_inspectors/appid/app_info_table.h"    // SF_APPID_MAX
#include "network_inspectors/appid/appid_peg_counts.h"
#include "network_inspectors/appid/appid_debug.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/MemoryLeakWarningPlugin.h>
#include <CppUTest/TestHarness.h>

// --- Minimal stubs required by appid_peg_counts.cc's init_pegs()/ctor path ---
// (AppIdThreadPegs ctor expands APPID_LOG, which references these.)
THREAD_LOCAL bool appid_trace_enabled = false;
THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
void appid_log(const snort::Packet*, const uint8_t, const char*, ...) { }

// print() emits its output through snort::LogText(). While capture_log is set,
// those lines accumulate in log_lines so a test can assert on what print()
// produced. Kept as a directly-written file-scope buffer rather than a pointer
// to a caller's local: the indirection made every write invisible to static
// analysis, which then reported the captured lines as an always-empty container.
static std::vector<std::string> log_lines;
static bool capture_log = false;

namespace snort
{
// Link stubs for symbols pulled in by appid_peg_counts.cc::print() and sf_ip.cc
// (print's LogLabel/LogText are exercised by the print test but are no-ops here).
void LogLabel(const char*, FILE*) { }
void LogText(const char* text, FILE*)
{
    if (capture_log and text)
        log_lines.push_back(text);
}
char* snort_strdup(const char* s) { char* p = new char[strlen(s) + 1]; strcpy(p, s); return p; }
}

namespace
{
constexpr AppId SEED_COUNT = 1000;
constexpr unsigned READER_THREADS = 4;
// appid_dynamic_sum[] has SF_APPID_MAX+1 fixed slots that print()/sum_stats index
// by an app_id's dynamic index (== map size at insertion). Real AppIds are always
// < SF_APPID_MAX, so keep the synthetic writer ids within that bound; otherwise the
// map grows past the array and print() reads out of bounds (a SIGSEGV in
// all_zeros() observed on FreeBSD -O2).
constexpr AppId APPID_ID_CAP = 39000;   // < SF_APPID_MAX (40000)
// Because the id space is bounded, the writer makes a FINITE number of real
// insertions. Once they are exhausted it would only re-emplace existing keys,
// which cannot rehash and so cannot corrupt a reader -- i.e. the run is only
// meaningful while this growth is in progress. Without the start barrier the
// writer can complete all of it before any reader runs; pinned to a single CPU
// that hid the missing lock in 28 of 30 runs.
// Readers do a bounded number of passes; the writer adds new ids for exactly as
// long as a reader is live. The start barrier -- not this count -- is what makes
// the window deterministic: it prevents the writer from finishing its insertions
// before the readers exist, which is the case that silently hid the missing lock.
constexpr long READ_ITERS = 1000;
// The start barrier is what structurally guarantees the window: the writer cannot
// begin until every reader is looping, so it can no longer complete all of its
// insertions before the readers exist (the case that hid the missing lock in 28 of
// 30 single-CPU runs). This floor verifies that guarantee held at runtime -- an
// overlap of zero means the barrier failed and the run proved nothing. It is
// deliberately minimal: under the fix the writer is legitimately blocked by the
// lock, so a larger floor would flake precisely because the fix works. Detection
// strength is established by the regression matrix in the PR, not by this number.
constexpr long MIN_OVERLAP_WRITES = 1;
// Safety cap so a pathological scheduler can never hang the barrier.
constexpr long MAX_BARRIER_SPINS = 100000000;

void seed_peg_ids()
{
    AppIdPegCounts::init_peg_info();    // create the shared appid_peg_ids map
    for (AppId i = 0; i < SEED_COUNT; ++i)
        AppIdPegCounts::add_app_peg_info("seed_" + std::to_string(i), i);
}

// Coordination shared by the writer and the readers of both tests.
struct RaceSync
{
    std::atomic<unsigned> readers_ready { 0 };    // readers that entered their read loop
    std::atomic<unsigned> readers_running { 0 };  // readers currently in that loop
    std::atomic<long> overlap_writes { 0 };       // insertions made with >= 1 reader running
    std::atomic<bool> race_detected { false };    // a reader observed a corrupt map
};

// Writer: waits for every reader to be looping, then grows the shared map with
// NEW ids so each emplace() can rehash under the readers.
void run_writer(RaceSync& sync, unsigned expected_readers)
{
    // Build the id strings BEFORE the barrier so the timed window contains only
    // emplace() work; that maximises the rehash pressure the readers see.
    std::vector<std::string> names;
    names.reserve(static_cast<size_t>(APPID_ID_CAP - SEED_COUNT));
    for (AppId id = SEED_COUNT; id < APPID_ID_CAP; ++id)
        names.push_back("dyn_" + std::to_string(id));

    for (long spins = 0; spins < MAX_BARRIER_SPINS &&
        sync.readers_ready.load(std::memory_order_acquire) < expected_readers; ++spins)
        std::this_thread::yield();

    // Insert NEW ids (each emplace can rehash) for exactly as long as a reader is
    // walking the map. Stopping once the last reader exits keeps the run short;
    // the barrier above guarantees this loop cannot finish before they start.
    for (size_t i = 0;
        i < names.size() && sync.readers_running.load(std::memory_order_relaxed) > 0; ++i)
    {
        AppIdPegCounts::add_app_peg_info(names[i], SEED_COUNT + static_cast<AppId>(i));
        sync.overlap_writes.fetch_add(1, std::memory_order_relaxed);
    }
}

// Joins the barrier, then repeats `body` until the writer reports growth done.
// A corrupt map surfaces as std::out_of_range from the peg_ids->at() in
// sum_stats(); catching it turns the regression into a clean test failure
// instead of an abort. (A corrupt node deref still crashes -- that is the
// backstop, and is what the field core showed.)
template<typename Body>
void run_reader_loop(RaceSync& sync, Body body)
{
    sync.readers_running.fetch_add(1, std::memory_order_relaxed);
    sync.readers_ready.fetch_add(1, std::memory_order_release);

    try
    {
        for (long n = 0; n < READ_ITERS; ++n)
            body();
    }
    catch (const std::out_of_range&)
    {
        sync.race_detected.store(true, std::memory_order_relaxed);
    }

    sync.readers_running.fetch_sub(1, std::memory_order_relaxed);
}

// Reader: mimics the packet-thread termination path -- init_pegs() snapshots the
// current shared map (appid_thread_pegs is THREAD_LOCAL), then sum_stats() walks
// it with peg_ids->at() while the writer mutates that same object.
void run_sum_stats_reader(RaceSync& sync)
{
    AppIdPegCounts::init_pegs();
    run_reader_loop(sync, [] { AppIdPegCounts::sum_stats(); });
    AppIdPegCounts::cleanup_pegs();
}
}

TEST_GROUP(appid_peg_counts_race)
{
};

// Race 1: writer add_app_peg_info() vs readers init_pegs()/sum_stats()
// on the shared appid_peg_ids map. Reproduces the teardown-vs-registration overlap.
TEST(appid_peg_counts_race, concurrent_add_vs_sum_stats)
{
    seed_peg_ids();

    RaceSync sync;

    std::vector<std::thread> readers;
    for (unsigned t = 0; t < READER_THREADS; ++t)
        readers.emplace_back([&sync] { run_sum_stats_reader(sync); });

    std::thread writer([&sync] { run_writer(sync, READER_THREADS); });

    writer.join();
    for (auto& r : readers)
        r.join();

    AppIdPegCounts::cleanup_peg_info();

    CHECK_TEXT(!sync.race_detected.load(std::memory_order_relaxed),
        "data race on appid_peg_ids: sum_stats() read a map corrupted by a "
             "concurrent add_app_peg_info() (peg_ids->at() threw std::out_of_range) "
             "-- appid_peg_ids_mutex is missing");

    const long overlap = sync.overlap_writes.load(std::memory_order_relaxed);
    const std::string overlap_msg = "inconclusive: only " + std::to_string(overlap) +
        " insertions overlapped a running reader (need >= " +
        std::to_string(MIN_OVERLAP_WRITES) + "); the start barrier did not hold, so no "
        "rehash raced a map walk and this run proves nothing";
    CHECK_TEXT(overlap >= MIN_OVERLAP_WRITES, overlap_msg.c_str());
}

// Race 2 (residual): print() reads *appid_peg_ids and appid_dynamic_sum with no
// lock, racing add_app_peg_info() (map mutation) and sum_stats() (dynamic_sum
// writes). Demonstrates why print()/show_dynamic_stats() also needs guarding.
TEST(appid_peg_counts_race, concurrent_print_vs_writers)
{
    seed_peg_ids();

    RaceSync sync;

    // Summer writes appid_dynamic_sum via sum_stats() (races print()'s reads)
    // and, like a terminating packet thread, walks the shared map.
    std::thread summer([&sync] { run_sum_stats_reader(sync); });

    // Two participants join the barrier: the summer and the printer below.
    std::thread writer([&sync] { run_writer(sync, 2); });

    // Printer runs on this thread and reads both appid_peg_ids and
    // appid_dynamic_sum (both unlocked pre-fix).
    run_reader_loop(sync, [] { AppIdPegCounts::print(); });

    writer.join();
    summer.join();

    AppIdPegCounts::cleanup_peg_info();

    CHECK_TEXT(!sync.race_detected.load(std::memory_order_relaxed),
        "data race on appid_peg_ids/appid_dynamic_sum: a stats reader saw "
             "state corrupted by a concurrent writer -- the print() guard and/or "
             "appid_peg_ids_mutex is missing");

    const long overlap = sync.overlap_writes.load(std::memory_order_relaxed);
    const std::string overlap_msg = "inconclusive: only " + std::to_string(overlap) +
        " insertions overlapped a running reader (need >= " +
        std::to_string(MIN_OVERLAP_WRITES) + "); the start barrier did not hold, so no "
        "rehash raced a map walk and this run proves nothing";
    CHECK_TEXT(overlap >= MIN_OVERLAP_WRITES, overlap_msg.c_str());
}

// appid_dynamic_sum[] is a fixed AppIdDynamicPeg[SF_APPID_MAX + 1] indexed by the
// dynamic index add_app_peg_info() assigns (the map size at insertion), with the
// last slot reserved for the unknown-app aggregate. Nothing bounds how many apps a
// detector package may register, so before add_app_peg_info() enforced the limit a
// large enough ODP handed out indices past the end of that array and sum_stats()
// and print() read and wrote out of bounds (ASAN: global-buffer-overflow).
TEST(appid_peg_counts_race, registration_bounded_by_dynamic_sum_capacity)
{
    // Previous cases leave totals in appid_dynamic_sum; start from a known state so
    // the assertions below only see what this case produced.
    AppIdPegCounts::cleanup_dynamic_sum();
    AppIdPegCounts::init_peg_info();

    const AppId over_limit_id = SF_APPID_MAX + 10;
    for (AppId id = 0; id <= over_limit_id; ++id)
        AppIdPegCounts::add_app_peg_info("app_" + std::to_string(id), id);

    AppIdPegCounts::init_pegs();

    // An app past the limit must not be tracked at all: its detections belong in
    // the unknown bucket rather than at an index outside appid_dynamic_sum[].
    AppIdPegCounts::inc_service_count(over_limit_id);
    AppIdPegCounts::sum_stats();

    log_lines.clear();
    capture_log = true;
    AppIdPegCounts::print();
    capture_log = false;

    AppIdPegCounts::cleanup_pegs();
    AppIdPegCounts::cleanup_peg_info();

    const std::string over_limit_name = "app_" + std::to_string(over_limit_id);
    bool counted_as_unknown = false;
    bool over_limit_tracked = false;
    for (const std::string& line : log_lines)
    {
        if (line.find("unknown") != std::string::npos)
            counted_as_unknown = true;
        if (line.find(over_limit_name) != std::string::npos)
            over_limit_tracked = true;
    }

    CHECK_TEXT(counted_as_unknown, "a detection for an app past the tracking limit "
        "was not counted in the unknown-app bucket");
    CHECK_TEXT(!over_limit_tracked, "an app past the tracking limit was given a "
        "dynamic index, which indexes outside appid_dynamic_sum[]");
}

// init_pegs() pre-sizes the thread local peg_counts from the shared map. That is
// an allocation change only, so this checks the observable contract it must not
// break: every registered app gets its own slot, counts land against the right
// app, and an unregistered app still falls through to the unknown bucket.
TEST(appid_peg_counts_race, init_pegs_snapshots_every_registered_app)
{
    AppIdPegCounts::cleanup_dynamic_sum();
    AppIdPegCounts::init_peg_info();

    // Enough entries that the map would otherwise rehash repeatedly while being
    // built, which is what the reserve() removes.
    constexpr AppId APP_COUNT = 5000;
    for (AppId id = 0; id < APP_COUNT; ++id)
        AppIdPegCounts::add_app_peg_info("snap_" + std::to_string(id), id);

    AppIdPegCounts::init_pegs();

    // One service detection for every registered app, plus one for an id that was
    // never registered (which must be counted as unknown, not dropped).
    for (AppId id = 0; id < APP_COUNT; ++id)
        AppIdPegCounts::inc_service_count(id);
    AppIdPegCounts::inc_service_count(APP_COUNT + 1);

    AppIdPegCounts::sum_stats();

    log_lines.clear();
    capture_log = true;
    AppIdPegCounts::print();
    capture_log = false;

    AppIdPegCounts::cleanup_pegs();
    AppIdPegCounts::cleanup_peg_info();

    // Every registered app must appear exactly once, so no id may share a slot
    // with another and none may be missing.
    unsigned app_lines = 0;
    unsigned unknown_lines = 0;
    for (const std::string& line : log_lines)
    {
        if (line.find("snap_") != std::string::npos)
            ++app_lines;
        else if (line.find("unknown") != std::string::npos)
            ++unknown_lines;
    }

    const std::string count_msg = "expected " + std::to_string(APP_COUNT) +
        " per-app lines from print(), got " + std::to_string(app_lines) +
        "; init_pegs() did not give every registered app its own dynamic slot";
    CHECK_TEXT(app_lines == APP_COUNT, count_msg.c_str());
    CHECK_TEXT(unknown_lines == 1, "a detection for an unregistered app was not "
        "counted in the unknown-app bucket");
}

int main(int argc, char** argv)
{
    // Disable CppUTest's (non-thread-safe) new/delete leak hooks for the whole
    // run, before the test runner starts -- this is the repo pattern for
    // threaded CppUTest tests (e.g. host_cache_module_test, unix_transport_test)
    // and avoids the leak detector racing/segfaulting on cross-thread allocations.
    // turnOffNewDeleteOverloads() is the API common to the bundled CppUTest 3.8
    // (CI) and 4.0 (dev).
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
