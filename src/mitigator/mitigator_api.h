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
// mitigator_api.h author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifndef MITIGATOR_API_H
#define MITIGATOR_API_H

#include <utility>

#ifdef CRASH_MITIGATOR

#include "mitigator/mitigator.h"

#define SETUP_MITIGATOR(mitigator_name, module_name, ...)                                   \
    static constexpr snort::MitigationPolicy mitigator_name##_policies_[] = __VA_ARGS__;    \
    static constexpr snort::MitigationConfig mitigator_name##_config_ =                     \
        snort::create_config<mitigator_name##_policies_,                                    \
            sizeof(mitigator_name##_policies_) / sizeof(snort::MitigationPolicy)>(          \
                module_name);                                                               \
    static snort::Mitigator mitigator_name { mitigator_name##_config_ }

#define SETUP_PACKET_MITIGATOR(mitigator_name)                                              \
    static snort::PacketMitigator mitigator_name

#else

#define SETUP_MITIGATOR(mitigator_name, ...)                            \
    constexpr auto mitigator_name = [](auto&& _f, auto&&... _args)      \
        -> decltype(auto) {                                             \
        return std::forward<decltype(_f)>(_f)(                          \
            std::forward<decltype(_args)>(_args)...);                   \
    }

#define SETUP_PACKET_MITIGATOR(mitigator_name)                          \
    constexpr auto mitigator_name = [](auto*, auto&& _f, auto&&... _args) \
        -> bool {                                                       \
        return std::forward<decltype(_f)>(_f)(                          \
            std::forward<decltype(_args)>(_args)...);                   \
    }

#endif

#endif
