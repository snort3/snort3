//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// mitigator.cc author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mitigator.h"

#include <cassert>

#include "detection/context_switcher.h"
#include "detection/ips_context.h"
#include "framework/ips_action.h"
#include "helpers/sigsafe.h"
#include "log/messages.h"
#include "main/analyzer.h"
#include "main/process.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq_instance.h"
#include "protocols/packet.h"
#include "utils/cpp_macros.h"
#include "utils/util.h"

#include "mitigator_context_processor.h"

static THREAD_LOCAL bool s_mitigation_active = false;

namespace snort
{

static std::mutex& s_mitigator_mutex()
{
    static std::mutex mtx;
    return mtx;
}

void mitigation_handle_signal(int32_t signal)
{
    if (s_mitigation_active)
    {
        remove_oops_handler();
        MitigationException::print_mitigation_info(signal, false);
        raise(signal);
        return;
    }

    s_mitigation_active = true;
    pthread_sigmask(SIG_SETMASK, &mitigator_pre_signal_mask(), nullptr);

    assert(signal == SIGILL or
        signal == SIGABRT or
        signal == SIGBUS or
        signal == SIGFPE or
        signal == SIGSEGV);

    throw MitigationException(signal);
}

sigset_t& s_pre_signal_mask()
{
    static THREAD_LOCAL sigset_t pre_sig_mask;
    return pre_sig_mask;
}

void mitigator_save_pre_signal_mask(const sigset_t& mask)
{ s_pre_signal_mask() = mask; }

const sigset_t& mitigator_pre_signal_mask()
{ return s_pre_signal_mask(); }

bool mitigator_is_enabled()
{
    if ( const auto* context = MitigationContextProcessor::global_context() )
    {
        return context->enabled;
    }

    ErrorMessage("ERROR: Could not get global mitigation context");

    return false;
}

bool mitigator_disable()
{
    if ( auto* context = MitigationContextProcessor::global_context() )
    {
        context->enabled = false;
        return true;
    }

    return false;
}

bool mitigator_enable_module(const std::string& module_name)
{
    std::lock_guard<std::mutex> lock(s_mitigator_mutex());
    if ( auto* context = MitigationContextProcessor::take_module_context(module_name) )
    {
        context->enabled = true;
        return true;
    }

    return false;
}

bool mitigator_disable_module(const std::string& module_name)
{
    std::lock_guard<std::mutex> lock(s_mitigator_mutex());
    if ( auto* context = MitigationContextProcessor::take_module_context(module_name) )
    {
        context->enabled = false;
        return true;
    }

    return false;
}

void create_context(const MitigationConfig& config)
{
    const auto module_name = std::string(config.module);
    if ( MitigationContextProcessor::get_module_context(module_name) == nullptr )
    {
        MitigationContextProcessor::emplace_context(module_name, false);
    }
}

void handle_block_action(Packet* p, const MitigationActionException& e)
{
    if ( p )
    {
        ++mitigator_stats.actions_block;
        WarningMessage("Mitigation action BLOCK applied to module %.*s\n",
            static_cast<int>(e.get_module().size()), e.get_module().data());
        DetectionEngine::disable_all(p);
        p->active->block_session(p, true);
        p->active->set_drop_reason("mitigator");
    }
    else
    {
        WarningMessage("Mitigation action BLOCK failed for module %.*s (no packet found), aborting.",
            static_cast<int>(e.get_module().size()), e.get_module().data());
        mitigator_disable();
        abort();
    }
}

void handle_drop_action(Packet* p, const MitigationActionException& e)
{
    if ( p )
    {
        ++mitigator_stats.actions_drop;
        WarningMessage("Mitigation action DROP applied to module %.*s\n",
            static_cast<int>(e.get_module().size()), e.get_module().data());
        p->active->drop_packet(p, true);
        p->active->set_drop_reason("mitigator");
    }
    else
    {
        WarningMessage("Mitigation action DROP failed for module %.*s (no packet found), aborting.",
            static_cast<int>(e.get_module().size()), e.get_module().data());
        mitigator_disable();
        abort();
    }
}

MitigationAction process_context()
{
    s_mitigation_active = false;

    return MitigationAction::Undefined;
}

MitigationAction process_context(const MitigationConfig& config)
{
    s_mitigation_active = false;

    MitigationModuleContext* context =
        MitigationContextProcessor::take_module_context(std::string(config.module));

    if ( !context )
    {
        ErrorMessage("Couldn't get context for module: %s\n", std::string(config.module).c_str());

        return MitigationAction::Undefined;
    }

    std::lock_guard<std::mutex> lock(s_mitigator_mutex());

    if ( !context->enabled )
        return MitigationAction::Abort;

    const MitigationPolicy* policies = context->policy ? context->policy : config.policies;
    const MitigationPolicy* policies_end = config.policies + config.num_policies;

    assert(policies);

    const auto signals_handled = ++context->signals_handled;

    while ( signals_handled > policies->threshold and (policies + 1) < policies_end )
        policies++;

    assert(policies);

    // if multiple policies with the same threshold - get the most severe action.
    while ( (policies + 1) != policies_end and
        policies->threshold == (policies + 1)->threshold and
        policies->threshold == signals_handled )
        policies++;

    assert(policies);

    context->policy = policies;

    if ( context->abort_on_flags & static_cast<uint32_t>(policies->action) )
        return MitigationAction::Abort;

    return policies->action;
}

static int mitigator_event_action(const char* action)
{
    const IpsAction::Type type = IpsAction::get_type(action);
    return IpsAction::is_valid_action(type) ? type : -1;
}

void finalize_mitigated_packet(Packet* p, const MitigationActionException& e)
{
    assert(p->daq_instance);

    // the stack has unwound to the catch boundary
    DetectionEngine::set_packet_abandoned(false);

    DAQ_Verdict verdict = DAQ_VERDICT_PASS;
    unsigned event_sid = 0;
    int event_action = -1;
    std::string daq_action;

    switch ( e.get_action() )
    {
    case MitigationAction::Block:
        verdict = DAQ_VERDICT_BLACKLIST;
        event_sid = MITIGATOR_EVENT_SIGNAL_BLOCKED;
        event_action = mitigator_event_action("block");
        daq_action = "block the flow";
        break;
    case MitigationAction::Drop:
        verdict = DAQ_VERDICT_BLOCK;
        event_sid = MITIGATOR_EVENT_SIGNAL_DROPPED;
        event_action = mitigator_event_action("drop");
        daq_action = "drop the packet";
        break;
    default:
        ErrorMessage("Unknown mitigation action while finalizing packet. Aborting.\n");
        mitigator_disable();
        abort();
    }

    {
        // A fault while logging must use the nested-fault path, not throw from a catch.
        struct MitigationActiveGuard
        {
            MitigationActiveGuard() { s_mitigation_active = true; }
            ~MitigationActiveGuard() { s_mitigation_active = false; }
        } guard;

        // events queued before the fault belong to the failed packet and must not be replayed
        DetectionEngine::clear_events(p);
        DetectionEngine::log_builtin_event(GID_MITIGATOR, event_sid, event_action);
    }

    p->pkth = nullptr;

    if ( !SnortConfig::get_conf()->adaptor_inline_mode() )
    {
        LogMessage("Mitigator attempted %s while IDS mode is enabled.\n", daq_action.c_str());
        verdict = DAQ_VERDICT_PASS;
    }

    Analyzer::get_local_analyzer()->clear_current_daq_message();
    p->daq_instance->finalize_message(p->daq_msg, verdict);

    Analyzer::get_switcher()->stop();
}

} // namespace snort

#ifdef UNIT_TEST

#include <thread>

#include "catch/snort_catch.h"
#include "main/process.h"
#include "mitigator/mitigator_api.h"

using namespace snort;

void setup_mitigation_signal_handler()
{
#ifdef HAVE_SIGACTION
    struct sigaction action;
    sigfillset(&action.sa_mask);
    action.sa_flags = SA_RESTART | SA_SIGINFO;
    action.sa_sigaction = [](int sig, siginfo_t*, void* ctx)
    {
        snort::mitigator_save_pre_signal_mask(static_cast<ucontext_t*>(ctx)->uc_sigmask);
        snort::mitigation_handle_signal(sig);
    };
    sigaction(SIGILL,  &action, nullptr);
    sigaction(SIGABRT, &action, nullptr);
    sigaction(SIGBUS,  &action, nullptr);
    sigaction(SIGFPE,  &action, nullptr);
    sigaction(SIGSEGV, &action, nullptr);
#else
    const auto handler = [](int sig)
    {
        sigset_t current;
        pthread_sigmask(SIG_SETMASK, nullptr, &current);
        sigdelset(&current, sig);
        snort::mitigator_save_pre_signal_mask(current);
        snort::mitigation_handle_signal(sig);
    };
    std::signal(SIGILL,  handler);
    std::signal(SIGABRT, handler);
    std::signal(SIGBUS,  handler);
    std::signal(SIGFPE,  handler);
    std::signal(SIGSEGV, handler);
#endif
}

// cppcheck-suppress-begin comparisonOfFuncReturningBoolError ; Catch2 false positive
TEST_CASE("Context successful creation", "[mitigator]")
{
    setup_mitigation_signal_handler();

    SETUP_MITIGATOR(raise_mitigator, "raise",
        { MitigationPolicy{ MitigationAction::Abort, 1u } });

    const MitigationModuleContext* context =
        MitigationContextProcessor::get_module_context(std::string(raise_mitigator.config.module));

    REQUIRE(context != nullptr);
    CHECK(context->enabled == false);
    CHECK(context->module == "raise");
}

TEST_CASE("get_module_context returns null for unregistered module", "[mitigator]")
{
    const MitigationModuleContext* ctx =
        MitigationContextProcessor::get_module_context("random_module");
    CHECK(ctx == nullptr);
}

TEST_CASE("mitigate completes normally when wrapped function does not raise", "[mitigator]")
{
    setup_mitigation_signal_handler();

    SETUP_MITIGATOR(normal_exec_mitigator, "normal_exec_test",
        { MitigationPolicy{ MitigationAction::Abort, 1u } });

    bool called = false;
    CHECK_NOTHROW(normal_exec_mitigator([&]() { called = true; }));
    CHECK(called == true);
}

TEST_CASE("mitigate propagates return value from wrapped function", "[mitigator]")
{
    SETUP_MITIGATOR(return_val_mitigator, "return_val_test",
        { MitigationPolicy{ MitigationAction::Abort, 1u } });

    const int result = return_val_mitigator([]() { return 42; });
    CHECK(result == 42);
}

TEST_CASE("mitigate returns move-only type without copying", "[mitigator]")
{
    struct MoveOnly
    {
        int value = 0;
        MoveOnly() = default;
        explicit MoveOnly(int v) : value(v) {}
        MoveOnly(MoveOnly&&) = default;
        MoveOnly& operator=(MoveOnly&&) = default;
        MoveOnly(const MoveOnly&) = delete;
        MoveOnly& operator=(const MoveOnly&) = delete;
    };

    static_assert(!std::is_copy_constructible_v<MoveOnly>,
        "MoveOnly must not be copy-constructible");

    SETUP_MITIGATOR(move_only_mitigator, "move_only_ret_test",
        { MitigationPolicy{ MitigationAction::Abort, 1u } });

    auto result = move_only_mitigator([]() { return MoveOnly{ 7 }; });
    CHECK(result.value == 7);
}

TEST_CASE("action deduction unknown module", "[mitigator]")
{
    MitigationConfig config { "unknown", nullptr, 0 };

    CHECK(process_context(config) == MitigationAction::Undefined);
}

TEST_CASE("action deduction different thresholds with distance 1", "[mitigator]")
{
    SETUP_MITIGATOR(module_dist1, "module_dist1",
    {
        MitigationPolicy{ MitigationAction::Ignore, 2u },
        MitigationPolicy{ MitigationAction::Abort, 3u }
    });
    REQUIRE(mitigator_enable_module("module_dist1"));

    CHECK(process_context(module_dist1.config) == MitigationAction::Ignore);
    CHECK(process_context(module_dist1.config) == MitigationAction::Ignore);
    CHECK(process_context(module_dist1.config) == MitigationAction::Abort);
}

TEST_CASE("action deduction different thresholds with distance > 1", "[mitigator]")
{
    SETUP_MITIGATOR(module_dist2, "module_dist2",
    {
        MitigationPolicy{ MitigationAction::Ignore, 1u },
        MitigationPolicy{ MitigationAction::Abort, 3u }
    });
    REQUIRE(mitigator_enable_module("module_dist2"));

    CHECK(process_context(module_dist2.config) == MitigationAction::Ignore);
    CHECK(process_context(module_dist2.config) == MitigationAction::Abort);
}

TEST_CASE("action deduction equal thresholds", "[mitigator]")
{
    SETUP_MITIGATOR(module_equal, "module_equal",
    {
        MitigationPolicy{ MitigationAction::Ignore, 1u },
        MitigationPolicy{ MitigationAction::Abort, 1u }
    });
    REQUIRE(mitigator_enable_module("module_equal"));

    CHECK(process_context(module_equal.config) == MitigationAction::Abort);
}

TEST_CASE("action deduction equal thresholds > 2", "[mitigator]")
{
    SETUP_MITIGATOR(module_equal2, "module_equal2",
    {
        MitigationPolicy{ MitigationAction::Ignore, 2u },
        MitigationPolicy{ MitigationAction::Abort, 2u }
    });
    REQUIRE(mitigator_enable_module("module_equal2"));

    CHECK(process_context(module_equal2.config) == MitigationAction::Ignore);
    CHECK(process_context(module_equal2.config) == MitigationAction::Abort);
}

TEST_CASE("global action - block threshold reached", "[mitigator]")
{
    SETUP_MITIGATOR(module_block_threshold, "module_block_threshold",
    {
        MitigationPolicy{ MitigationAction::Ignore, 2u },
        MitigationPolicy{ MitigationAction::Block, 4u },
        MitigationPolicy{ MitigationAction::Abort, 5u }
    });
    REQUIRE(mitigator_enable_module("module_block_threshold"));

    CHECK(process_context(module_block_threshold.config) == MitigationAction::Ignore);
    CHECK(process_context(module_block_threshold.config) == MitigationAction::Ignore);

    CHECK(process_context(module_block_threshold.config) == MitigationAction::Block);
    CHECK(process_context(module_block_threshold.config) == MitigationAction::Block);

    CHECK(process_context(module_block_threshold.config) == MitigationAction::Abort);
}

TEST_CASE("per-module disable forces crash instead of block", "[mitigator]")
{
    SETUP_MITIGATOR(module_block_disable, "module_block_disable",
    {
        MitigationPolicy{ MitigationAction::Block, 1u },
        MitigationPolicy{ MitigationAction::Abort, 3u }
    });
    REQUIRE(mitigator_enable_module("module_block_disable"));

    // Block returned while module is enabled
    CHECK(process_context(module_block_disable.config) == MitigationAction::Block);

    // Disable module — should force Crash regardless of policy
    mitigator_disable_module("module_block_disable");
    CHECK(process_context(module_block_disable.config) == MitigationAction::Abort);

    // Re-enable module — Block resumes from saved policy position
    mitigator_enable_module("module_block_disable");
    CHECK(process_context(module_block_disable.config) == MitigationAction::Abort);
}

TEST_CASE("always_terminate_flags with block forces crash", "[mitigator]")
{
    SETUP_MITIGATOR(module_block_terminate, "module_block_terminate",
    {
        MitigationPolicy{ MitigationAction::Block, 2u },
        MitigationPolicy{ MitigationAction::Abort, 5u }
    });
    REQUIRE(mitigator_enable_module("module_block_terminate"));

    MitigationModuleContext* ctx =
        MitigationContextProcessor::take_module_context("module_block_terminate");
    REQUIRE(ctx != nullptr);
    ctx->abort_on_flags = static_cast<uint32_t>(MitigationAction::Block);

    CHECK(process_context(module_block_terminate.config) == MitigationAction::Abort);
}

TEST_CASE("block and crash at equal threshold picks crash", "[mitigator]")
{
    SETUP_MITIGATOR(module_block_equal_crash, "module_block_equal_crash",
    {
        MitigationPolicy{ MitigationAction::Block, 1u },
        MitigationPolicy{ MitigationAction::Abort, 1u }
    });
    REQUIRE(mitigator_enable_module("module_block_equal_crash"));

    CHECK(process_context(module_block_equal_crash.config) == MitigationAction::Abort);
}

TEST_CASE("block as immediate first action", "[mitigator]")
{
    SETUP_MITIGATOR(module_block_first, "module_block_first",
    {
        MitigationPolicy{ MitigationAction::Block, 3u },
        MitigationPolicy{ MitigationAction::Abort, 4u }
    });
    REQUIRE(mitigator_enable_module("module_block_first"));

    CHECK(process_context(module_block_first.config) == MitigationAction::Block);
    CHECK(process_context(module_block_first.config) == MitigationAction::Block);
    CHECK(process_context(module_block_first.config) == MitigationAction::Block);

    CHECK(process_context(module_block_first.config) == MitigationAction::Abort);
}

TEST_CASE("mitigate throws MitigationActionException on Block", "[mitigator]")
{
    setup_mitigation_signal_handler();

    SETUP_MITIGATOR(module_throw_block, "module_throw_block",
    {
        MitigationPolicy{ MitigationAction::Block, 1u },
        MitigationPolicy{ MitigationAction::Abort, 3u }
    });
    REQUIRE(mitigator_enable_module("module_throw_block"));

    auto raise_signal = []() { raise(SIGSEGV); };

    try
    {
        module_throw_block(raise_signal);
        FAIL("Expected MitigationActionException to be thrown");
    }
    catch ( MitigationActionException& e )
    {
        CHECK(e.get_action() == MitigationAction::Block);
        CHECK(e.get_module() == "module_throw_block");
    }
}

TEST_CASE("mitigate throws MitigationActionException on Drop", "[mitigator]")
{
    setup_mitigation_signal_handler();

    SETUP_MITIGATOR(module_throw_drop, "module_throw_drop",
    {
        MitigationPolicy{ MitigationAction::Drop, 1u },
        MitigationPolicy{ MitigationAction::Abort, 3u }
    });
    REQUIRE(mitigator_enable_module("module_throw_drop"));

    auto raise_signal = []() { raise(SIGSEGV); };

    try
    {
        module_throw_drop(raise_signal);
        FAIL("Expected MitigationActionException to be thrown");
    }
    catch ( MitigationActionException& e )
    {
        CHECK(e.get_action() == MitigationAction::Drop);
        CHECK(e.get_module() == "module_throw_drop");
    }
}

TEST_CASE("always_terminate_flags with drop forces crash", "[mitigator]")
{
    SETUP_MITIGATOR(module_drop_terminate, "module_drop_terminate",
    {
        MitigationPolicy{ MitigationAction::Drop, 2u },
        MitigationPolicy{ MitigationAction::Abort, 5u }
    });
    REQUIRE(mitigator_enable_module("module_drop_terminate"));

    MitigationModuleContext* ctx =
        MitigationContextProcessor::take_module_context("module_drop_terminate");
    REQUIRE(ctx != nullptr);
    ctx->abort_on_flags = static_cast<uint32_t>(MitigationAction::Drop);

    CHECK(process_context(module_drop_terminate.config) == MitigationAction::Abort);
}

TEST_CASE("drop and block at equal threshold picks block", "[mitigator]")
{
    SETUP_MITIGATOR(module_drop_equal_block, "module_drop_equal_block",
    {
        MitigationPolicy{ MitigationAction::Drop, 1u },
        MitigationPolicy{ MitigationAction::Block, 1u },
        MitigationPolicy{ MitigationAction::Abort, 3u }
    });
    REQUIRE(mitigator_enable_module("module_drop_equal_block"));

    CHECK(process_context(module_drop_equal_block.config) == MitigationAction::Block);
    CHECK(process_context(module_drop_equal_block.config) == MitigationAction::Abort);
    CHECK(process_context(module_drop_equal_block.config) == MitigationAction::Abort);
}

TEST_CASE("PacketMitigator returns true on normal completion", "[mitigator]")
{
    Packet p;
    PacketMitigator pm;
    auto always_true = [](){ return true; };

    bool result = pm(&p, always_true);
    CHECK(result);
}

TEST_CASE("PacketMitigator returns false on incomplete", "[mitigator]")
{
    Packet p;
    PacketMitigator pm;
    auto always_false = [](){ return false; };

    bool result = pm(&p, always_false);
    CHECK_FALSE(result);
}

TEST_CASE("signal mask is restored after mitigation", "[mitigator]")
{
    setup_mitigation_signal_handler();

    SETUP_MITIGATOR(module_mask_restore, "module_mask_restore",
    {
        MitigationPolicy{ MitigationAction::Ignore, 1u },
        MitigationPolicy{ MitigationAction::Abort, 3u }
    });
    REQUIRE(mitigator_enable_module("module_mask_restore"));

    sigset_t block_usr1, prev_mask;
    sigemptyset(&block_usr1);
    sigaddset(&block_usr1, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &block_usr1, &prev_mask);

    module_mask_restore([](){ raise(SIGSEGV); });

    sigset_t post_mask;
    pthread_sigmask(SIG_SETMASK, nullptr, &post_mask);

    pthread_sigmask(SIG_SETMASK, &prev_mask, nullptr);

    CHECK(sigismember(&post_mask, SIGUSR1) == 1);
    CHECK(sigismember(&post_mask, SIGSEGV) == 0);
}

// cppcheck-suppress-end comparisonOfFuncReturningBoolError

#endif
