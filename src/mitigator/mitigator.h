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
// mitigator.h author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifndef MITIGATOR_H
#define MITIGATOR_H

#include <cstdlib>

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "main/snort_types.h"
#include "main/thread.h"

#include "mitigator_action_exception.h"
#include "mitigator_exception.h"
#include "mitigator_helpers.h"
#include "mitigator_module.h"
#include "mitigator_types.h"

#ifdef ENABLE_DETECTION_OFFLOAD
#error Stop. Crash Mitigation is not supported with detection offload.
#endif

namespace snort
{

void mitigation_handle_signal(int32_t sig);

SO_PUBLIC void mitigator_save_pre_signal_mask(const sigset_t& mask);
SO_PUBLIC const sigset_t& mitigator_pre_signal_mask();

bool mitigator_is_enabled();
SO_PUBLIC bool mitigator_disable();
bool mitigator_enable_module(const std::string& module_name);
bool mitigator_disable_module(const std::string& module_name);

void handle_block_action(Packet* p, const MitigationActionException& e);
void handle_drop_action(Packet* p, const MitigationActionException& e);
SO_PUBLIC void create_context(const MitigationConfig& config);
SO_PUBLIC MitigationAction process_context();
SO_PUBLIC MitigationAction process_context(const MitigationConfig& config);

template<const auto& policies, size_t num_policies>
constexpr MitigationConfig create_config(std::string_view module)
{
    static_assert(thresholds_nonzero<policies, num_policies>(), "threshold cannot be 0");
    static_assert(thresholds_ascending<policies, num_policies>(), "thresholds must be equal or ascending");
    static_assert(actions_defined<policies, num_policies>(), "action cannot be undefined");
    static_assert(actions_ascending<policies, num_policies>(), "actions must be ascending");
    static_assert(has_crash_action<policies, num_policies>(), "'abort' action is required");

    return MitigationConfig{ module, policies, num_policies };
}

template<typename F, typename... Args>
SO_PUBLIC decltype(auto) mitigate(const MitigationConfig& config, F&& func, Args&&... args)
{
    using Result = std::invoke_result_t<F, Args...>;
    try
    {
        if constexpr ( std::is_void_v<Result> )
        {
            func(std::forward<Args>(args)...);
            return;
        }
        else
        {
            return func(std::forward<Args>(args)...);
        }
    }
    catch ( MitigationException& )
    {
        ++mitigator_stats.signals_received;
        const auto action = process_context(config);

        switch( action )
        {
        case MitigationAction::Ignore:
            ++mitigator_stats.actions_ignore;
            WarningMessage("Mitigation action IGNORE applied to module %.*s\n",
                static_cast<int>(config.module.size()), config.module.data());
            DetectionEngine::queue_event(GID_MITIGATOR, MITIGATOR_EVENT_SIGNAL_IGNORED);
            break;
        case MitigationAction::Block:       // fallthrough
        case MitigationAction::Drop:
            // contexts released while unwinding to PacketMitigator must not log their events
            DetectionEngine::set_packet_abandoned();
            throw MitigationActionException(action, config.module);
        case MitigationAction::Undefined:   // fallthrough
        case MitigationAction::Abort:
            mitigator_disable();
            abort();
        }
    }

    if constexpr ( !std::is_void_v<Result> )
        return Result{};
}

inline void handle_mitigation_action(Packet* p, const MitigationActionException& e)
{
    switch ( e.get_action() )
    {
    case MitigationAction::Block:
    {
        handle_block_action(p, e);
        break;
    }
    case MitigationAction::Drop:
        handle_drop_action(p, e);
        break;
    default:
        mitigator_disable();
        abort();
    }
}

struct SO_PUBLIC Mitigator
{
    MitigationConfig config;

    explicit Mitigator(const MitigationConfig& cfg) : config(cfg)
    {
        create_context(config);
    }

    template<typename F, typename... Args>
    decltype(auto) operator()(F&& f, Args&&... args)
    {
        return mitigate(config, std::forward<F>(f), std::forward<Args>(args)...);
    }
};

SO_PUBLIC void finalize_mitigated_packet(Packet* p, const MitigationActionException& e);

struct SO_PUBLIC PacketMitigator
{
    template<typename F, typename... Args>
    bool operator()(Packet* p, F&& func, Args&&... args)
    {
        try
        {
            return func(std::forward<Args>(args)...);
        }
        catch ( MitigationActionException& e )
        {
            handle_mitigation_action(p, e);
            finalize_mitigated_packet(p, e);
            return false;
        }
    }
};

} // namespace snort

#endif
