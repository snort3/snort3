//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "search_engines.h"

#include "managers/plugin_manager.h"

using namespace snort;

extern const BaseApi* se_ac_bnfa[];
extern const BaseApi* se_ac_full[];

#ifdef STATIC_SEARCH_ENGINES
#ifdef HAVE_HYPERSCAN
extern const BaseApi* se_hyperscan[];
#endif
#endif

void load_search_engines()
{
    PluginManager::load_plugins(se_ac_bnfa);
    PluginManager::load_plugins(se_ac_full);

#ifdef STATIC_SEARCH_ENGINES
#ifdef HAVE_HYPERSCAN
    PluginManager::load_plugins(se_hyperscan);
#endif
#endif
}

