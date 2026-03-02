//--------------------------------------------------------------------------
// Copyright (C) 2016-2026 Cisco and/or its affiliates. All rights reserved.
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
// swapper.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "swapper.h"

#include "managers/inspector_manager.h"
#include "managers/plugin_manager.h"

#include "analyzer.h"
#include "snort.h"
#include "snort_config.h"

using namespace snort;

Swapper::Swapper(SnortConfig* s)
{
    new_conf = s;
    new_iv = InspectorManager::get_map();
}

Swapper::Swapper(const SnortConfig* sold, SnortConfig* snew)
{
    old_conf = sold;
    new_conf = snew;
    new_iv = InspectorManager::get_map();
}

Swapper::~Swapper()
{
    if ( new_conf and old_conf )
    {
        //transfer ownership of mp_dbus to new config
        if ( new_conf->mp_dbus == old_conf->mp_dbus )
            const_cast<SnortConfig*>(old_conf)->mp_dbus = nullptr;
    }

    if ( old_conf )
    {
        PluginManager::set_plugins(old_conf->plug_set);
        InspectorManager::revert_map();
        delete old_conf;
        PluginManager::clear_plugins();
        InspectorManager::restore_map();
    }
}

void Swapper::apply(Analyzer& analyzer)
{
    if ( new_iv )
        InspectorManager::set_map(new_iv);

    if ( new_conf )
    {
        const auto cur_conf = SnortConfig::get_conf();
        const bool reload = cur_conf and cur_conf != new_conf;
        SnortConfig::set_conf(new_conf);

        if ( reload )
            analyzer.reinit(new_conf);
    }
}

void Swapper::finish()
{
    InspectorManager::thread_term_removed();
}

