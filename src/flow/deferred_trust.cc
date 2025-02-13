//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
// deferred_trust.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "deferred_trust.h"

#include "packet_io/active.h"

using namespace snort;

void DeferredTrust::set_deferred_trust(unsigned module_id, bool on)
{
    if (on)
    {
        if (deferred_trust_modules.empty())
        {
            if (TRUST_DEFER_DO_TRUST == deferred_trust)
                deferred_trust = TRUST_DEFER_DEFERRING;
            else
                deferred_trust = TRUST_DEFER_ON;
        }
        auto element = deferred_trust_modules.begin();
        for (; element != deferred_trust_modules.end() && *element != module_id; ++element);
        if (element == deferred_trust_modules.end())
            deferred_trust_modules.emplace_front(module_id);
    }
    else if (!deferred_trust_modules.empty())
    {
        deferred_trust_modules.remove(module_id);
        if (deferred_trust_modules.empty())
        {
            if (TRUST_DEFER_DEFERRING == deferred_trust)
                deferred_trust = TRUST_DEFER_DO_TRUST;
            else
                deferred_trust = TRUST_DEFER_OFF;
        }
    }
}

void DeferredTrust::finalize(Active& active)
{
    if (active.session_was_blocked())
        clear();
    else if (TRUST_DEFER_DO_TRUST == deferred_trust && active.session_was_allowed())
    {
        active.set_trust();
        clear();
    }
    else if ((TRUST_DEFER_ON == deferred_trust || TRUST_DEFER_DEFERRING == deferred_trust)
        && active.session_was_trusted())
    {
        // This is the case where defer was called after session trust while processing
        // the same packet
        deferred_trust = TRUST_DEFER_DEFERRING;
        active.set_allow();
    }
}
