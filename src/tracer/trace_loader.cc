//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// trace_loader.cc author Pranav Jain <ppramodj@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_loader.h"

#include "framework/tracer.h"
#include "managers/plugin_manager.h"

using namespace snort;

void load_trace_loggers()
{
#ifdef STATIC_TRACERS
    extern const BaseApi* file_trace_logger[];
    extern const BaseApi* stdout_trace_logger[];
    extern const BaseApi* syslog_trace_logger[];

    PluginManager::load_plugins(file_trace_logger);
    PluginManager::load_plugins(stdout_trace_logger);
    PluginManager::load_plugins(syslog_trace_logger);
#endif
}

