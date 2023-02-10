//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// deferred_trust.h author Ron Dempster <rdempste@cisco.com>

#ifndef DEFERRED_TRUST_H
#define DEFERRED_TRUST_H

#include <cstdint>
#include <forward_list>

#include "main/snort_types.h"

namespace snort
{

class Active;
class Flow;
struct Packet;

class DeferredTrust
{
    // This class is used to delay session trust. This is used in cases where
    // a module needs to continue inspecting a session to enforce policy.
    // A module calls set_deferred_trust with the on parameter true to begin
    // deferring. The sets the state to TRUST_DEFER_ON. If trust session is called
    // while deferring, the state is changed to TRUST_DEFER_DEFERRING to the trust action.
    // A module calls set_deferred_trust with the on parameter false to stop deferring.
    // When all modules have stopped deferring, the state is checked. If the state is
    // TRUST_DEFER_DEFERRING, the state is changed to TRUST_DEFER_DO_TRUST. Otherwise, the state
    // is set to TRUST_DEFER_OFF.
    // The TRUST_DEFER_DO_TRUST state is checked at the end of packet processing. If the state
    // is TRUST_DEFER_DO_TRUST and the action is ACT_ALLOW, the session is trusted.
    // If a drop, block or reset action occurs while deferring, deferring is stopped and the
    // block or blocklist version is enforced.
    // The module_id, a unique module identifier created by calling
    // FlowData::create_flow_data_id(), is used to track the modules that are currently deferring.
    // This allows the module to use trusted deferring without needing to track the deferring
    // state of the module.
    enum DeferredTrustState : uint8_t
    {
        TRUST_DEFER_OFF = 0,
        TRUST_DEFER_ON,
        TRUST_DEFER_DEFERRING,
        TRUST_DEFER_DO_TRUST,
    };

public:
    DeferredTrust() = default;
    ~DeferredTrust() = default;
    SO_PUBLIC void set_deferred_trust(unsigned module_id, bool on);
    bool is_active()
    { return TRUST_DEFER_ON == deferred_trust || TRUST_DEFER_DEFERRING == deferred_trust; }
    bool try_trust()
    {
        if (TRUST_DEFER_ON == deferred_trust)
            deferred_trust = TRUST_DEFER_DEFERRING;
        return TRUST_DEFER_DEFERRING != deferred_trust;
    }
    bool is_deferred()
    { return TRUST_DEFER_DEFERRING == deferred_trust; }
    void clear()
    {
        deferred_trust = TRUST_DEFER_OFF;
        deferred_trust_modules.clear();
    }
    void finalize(Active&);

protected:
    std::forward_list<unsigned> deferred_trust_modules;
    DeferredTrustState deferred_trust = TRUST_DEFER_OFF;
};

}

#endif
