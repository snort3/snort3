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
// trace_logger_manager.h author Pranav Jain <ppramodj@cisco.com>

#ifndef TRACE_LOGGER_MANAGER_H
#define TRACE_LOGGER_MANAGER_H

#include <string>
#include <unordered_map>
#include <vector>

#include "framework/tracer.h"

class PlugInterface;
class TraceConfig;

//--------------------------------------------------------------------------
// TraceLoggerManager - Central manager for trace logger plugins
//--------------------------------------------------------------------------

class TraceLoggerManager
{
public:
    static class PlugInterface* get_interface(const snort::TraceLogApi*);
    static snort::TraceLoggerPlug* get_logger(const std::string& name);
    static snort::TraceLoggerPlug* set_logger(const std::string& name);
    static void instantiate_default_loggers(TraceConfig*);

private:
    TraceLoggerManager() = delete;
    ~TraceLoggerManager() = delete;
    TraceLoggerManager(const TraceLoggerManager&) = delete;
    TraceLoggerManager& operator=(const TraceLoggerManager&) = delete;
};

#endif
