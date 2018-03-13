//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// piglet_plugins.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "piglet_plugins.h"

#include "managers/plugin_manager.h"

using namespace snort;

extern const BaseApi* pp_codec;
extern const BaseApi* pp_inspector;
extern const BaseApi* pp_ips_action;
extern const BaseApi* pp_ips_option;
extern const BaseApi* pp_logger;
extern const BaseApi* pp_search_engine;
extern const BaseApi* pp_so_rule;
extern const BaseApi* pp_test;

static const BaseApi* pp_piglets[] =
{
    pp_codec,
    pp_inspector,
    pp_ips_action,
    pp_ips_option,
    pp_logger,
    pp_search_engine,
    pp_so_rule,
    pp_test,
    nullptr
};

void load_piglets()
{
    PluginManager::load_plugins(pp_piglets);
}

