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

#ifndef MITIGATOR_HELPERS_H
#define MITIGATOR_HELPERS_H

#include "mitigator_types.h"

namespace snort
{

template<const auto& policies, size_t num_policies>
constexpr bool thresholds_nonzero()
{
    for (size_t i = 0; i < num_policies; ++i)
        if (policies[i].threshold == 0u)
            return false;
    return true;
}

template<const auto& policies, size_t num_policies>
constexpr bool actions_defined()
{
    for (size_t i = 0; i < num_policies; ++i)
        if (policies[i].action == MitigationAction::Undefined)
            return false;
    return true;
}

template<const auto& policies, size_t num_policies>
constexpr bool actions_ascending()
{
    MitigationAction prev = MitigationAction::Undefined;
    for (size_t i = 0; i < num_policies; ++i)
    {
        if (static_cast<uint8_t>(prev) >=
            static_cast<uint8_t>(policies[i].action))
            return false;
        prev = policies[i].action;
    }
    return true;
}

template<const auto& policies, size_t num_policies>
constexpr bool has_crash_action()
{
    for (size_t i = 0; i < num_policies; ++i)
        if (policies[i].action == MitigationAction::Abort)
            return true;
    return false;
}

template<const auto& policies, size_t num_policies>
constexpr bool thresholds_ascending()
{
    uint32_t prev { 0u };
    for (size_t i = 0; i < num_policies; ++i)
    {
        if (prev > policies[i].threshold)
            return false;
        prev = policies[i].threshold;
    }
    return true;
}

} // namespace snort

#endif
