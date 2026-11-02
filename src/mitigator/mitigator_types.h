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
// mitigator_types.h author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifndef MITIGATOR_TYPES_H
#define MITIGATOR_TYPES_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>

#define GID_MITIGATOR 156

#define MITIGATOR_EVENT_SIGNAL_ABORTED  1 // reserved for future use
#define MITIGATOR_EVENT_SIGNAL_IGNORED  2
#define MITIGATOR_EVENT_SIGNAL_DROPPED  3
#define MITIGATOR_EVENT_SIGNAL_BLOCKED  4

namespace snort
{

enum class MitigationAction : uint32_t
{
    Undefined = 1u << 0u,
    Ignore    = 1u << 1u,
    Drop      = 1u << 2u,
    Block     = 1u << 3u,
    Abort     = 1u << 4u,
};

struct MitigationPolicy
{
    MitigationAction action { MitigationAction::Undefined };
    uint32_t threshold { 0u };
};

struct MitigationConfig
{
    std::string_view module;
    const MitigationPolicy* policies = nullptr;
    const uint32_t num_policies = 0;
};

struct MitigationOptions
{
    bool enabled { false };
};

struct MitigationGlobalContext
{
    std::atomic<uint32_t> signals_handled { 0u };
    std::atomic<bool> enabled { false };
};

struct MitigationModuleContext
{
    std::string module;
    bool enabled { false };
    uint32_t abort_on_flags { 0u };
    std::atomic<uint32_t> signals_handled { 0u };
    const MitigationPolicy* policy { nullptr };
};

using MitigationModule = std::string;
using MitigationModuleContextPtr = std::unique_ptr<MitigationModuleContext>;
using MitigationModuleContexts = std::unordered_map<MitigationModule, MitigationModuleContextPtr>;

} // namespace snort

#endif
