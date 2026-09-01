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
// reload_survivor_subscriptions.h author Bhumika Sachdeva <bsachdev@cisco.com>

#ifndef RELOAD_SURVIVOR_SUBSCRIPTIONS_H
#define RELOAD_SURVIVOR_SUBSCRIPTIONS_H

// Opt-in DataBus subscription facility for inspectors that outlive a
// reload via surviving flow refs.
//
// This is the plugin-facing surface: subscribe() only.  Lifecycle entry
// points are framework-internal, in reload_survivor_subscriptions_impl.h.
//
// Subscriber obligation
// ---------------------
// A handler registered here may be dispatched after the owning inspector's
// object-level tterm() has run.  The framework drains callbacks that are
// already in flight before calling tterm(); it does not prevent a later
// dispatch.  A survivor handler must therefore:
//   - not touch state that its inspector's tterm() releases;
//   - confirm it owns a shared flow-data slot before downcasting that slot
//     to its own type, and decline a slot owned by another inspector;
//   - be idempotent where no owner stamp exists, such as an absent shared
//     slot, since every surviving generation reaches that path;
//   - hold its configuration by shared snapshot rather than by a pointer
//     into the inspector, which may already be gone.
// A handler that cannot meet this should stay an ordinary DataBus
// subscriber and be re-established by the new configuration instead.

#include <functional>

#include "main/snort_types.h"

struct InspectionPolicy;
struct NetworkPolicy;

namespace snort
{
class DataHandler;
class Inspector;
struct PubKey;

class ReloadSurvivorSubscriptions
{
public:
    using Factory = std::function<DataHandler*()>;

    ReloadSurvivorSubscriptions(NetworkPolicy& np, InspectionPolicy& ip, Inspector& survivor);

    // handed to plugins by reference only; never constructed or copied by them
    ReloadSurvivorSubscriptions(const ReloadSurvivorSubscriptions&) = delete;
    ReloadSurvivorSubscriptions& operator=(const ReloadSurvivorSubscriptions&) = delete;

    SO_PUBLIC void subscribe(const char* key, const PubKey& pub, unsigned eid, Factory factory);

private:
    NetworkPolicy& np;
    InspectionPolicy& ip;
    Inspector& survivor;
};

}

#endif
