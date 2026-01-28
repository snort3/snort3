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
// trace_logger_manager.cc author Pranav Jain <ppramodj@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "managers/trace_logger_manager.h"

#include <iostream>
#include <map>
#include <unordered_map>
#include <vector>

#include "main/thread.h"
#include "main/thread_config.h"

using namespace snort;

//--------------------------------------------------------------------------
// TraceLoggerManager Private Data
//--------------------------------------------------------------------------

struct TraceLoggerElem
{
    // Default constructor for STL compatibility
    TraceLoggerElem() : name(), api(nullptr), module(nullptr), thread_loggers() { }

    TraceLoggerElem(const std::string& name, const TraceLogApi* api, Module* mod)
        : name(name), api(api), module(mod), thread_loggers(ThreadConfig::get_instance_max(), nullptr)
    { }

    std::string name;
    const TraceLogApi* api;
    Module* module;
    std::vector<TraceLoggerPlug*> thread_loggers;
};

typedef std::map<std::string, TraceLoggerElem> LoggerMap;
static LoggerMap s_loggers;
static std::map<std::string, const TraceLogApi*> s_trace_plugins;

//--------------------------------------------------------------------------
// TraceLoggerManager Implementation
//--------------------------------------------------------------------------

void TraceLoggerManager::add_plugin(const TraceLogApi* api)
{
    if (api && api->base.name)
        s_trace_plugins[api->base.name] = api;
}

void TraceLoggerManager::dump_plugins()
{
    std::cout << "Registered TraceLogger plugins:\n";
    for (const auto& kv : s_trace_plugins)
        std::cout << "  " << kv.first << "\n";
}

void TraceLoggerManager::release_plugins()
{
    for (auto& kv : s_loggers)
    {
        TraceLoggerElem& elem = kv.second;
        if (elem.api && elem.api->dtor)
        {
            for (auto* logger : elem.thread_loggers)
            {
                if (logger)
                    elem.api->dtor(logger);
            }
        }
    }
    s_loggers.clear();
    s_trace_plugins.clear();
}

void TraceLoggerManager::instantiate(const TraceLogApi* api, Module* mod, const std::string& name)
{
    if (!api || !api->ctor)
        return;
        
    if (s_loggers.find(name) != s_loggers.end())
        return; // already instantiated

    TraceLoggerElem elem(name, api, mod);
    
    // Only instantiate for the main thread here; thread_init will handle others
    TraceLoggerPlug* logger = api->ctor(mod, name);
    if (logger)
    {
        logger->set_api(api);
        elem.thread_loggers.resize(ThreadConfig::get_instance_max(), nullptr);
        elem.thread_loggers[0] = logger;
        s_loggers[name] = std::move(elem);
    }
}

bool TraceLoggerManager::is_instantiated(const std::string& name)
{
    return s_loggers.find(name) != s_loggers.end();
}

void TraceLoggerManager::thread_init()
{
    unsigned instance = get_instance_id();

    for (auto& kv : s_loggers)
    {
        TraceLoggerElem& elem = kv.second;
        
        if (elem.thread_loggers.size() <= instance)
            elem.thread_loggers.resize(instance + 1, nullptr);

        if (!elem.thread_loggers[instance] && elem.api && elem.api->ctor)
        {
            // Create logger instance for this thread
            TraceLoggerPlug* logger = elem.api->ctor(elem.module, elem.name);
            if (logger)
            {
                logger->set_api(elem.api);
                elem.thread_loggers[instance] = logger;
            }
        }
    }
}

void TraceLoggerManager::thread_term()
{
    unsigned instance = get_instance_id();

    // Main thread (instance 0) should not destroy its loggers here
    // as they may still be needed during shutdown operations like reap_command().
    // Main thread loggers will be cleaned up in release_plugins() during manager termination.
    if (instance == 0)
        return;

    for (auto& kv : s_loggers)
    {
        TraceLoggerElem& elem = kv.second;
        
        if (elem.api && elem.api->dtor && 
            elem.thread_loggers.size() > instance && 
            elem.thread_loggers[instance])
        {
            elem.api->dtor(elem.thread_loggers[instance]);
            elem.thread_loggers[instance] = nullptr;
        }
    }
}

TraceLoggerPlug* TraceLoggerManager::get_logger(const std::string& name)
{
    unsigned instance = get_instance_id();

    auto it = s_loggers.find(name);
    if (it != s_loggers.end())
    {
        TraceLoggerElem& elem = it->second;
        if (elem.thread_loggers.size() > instance && elem.thread_loggers[instance])
            return elem.thread_loggers[instance];
    }
    
    return nullptr;
}

std::unordered_map<std::string, std::vector<TraceLoggerPlug*>> 
TraceLoggerManager::get_all_loggers()
{
    std::unordered_map<std::string, std::vector<TraceLoggerPlug*>> all_loggers;

    for (const auto& [name, elem] : s_loggers)
    {
        std::vector<TraceLoggerPlug*> instances;

        for (size_t i = 0; i < elem.thread_loggers.size(); ++i)
        {
            if (elem.thread_loggers[i])
                instances.push_back(elem.thread_loggers[i]);
        }

        if (!instances.empty())
            all_loggers[name] = std::move(instances);
    }

    return all_loggers;
}
