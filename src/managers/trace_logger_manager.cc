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

#include "trace_logger_manager.h"

#include <iostream>
#include <map>
#include <unordered_map>
#include <vector>

#include "framework/module.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "main/thread_config.h"
#include "trace/trace_config.h"

#include "plugin_manager.h"
#include "plug_interface.h"

using namespace snort;

//--------------------------------------------------------------------------
// plugin interface foo
//--------------------------------------------------------------------------

class TracePlugIntf : public PlugInterface
{
public:
    TracePlugIntf(const TraceLogApi* api) : api(api) { }

    ~TracePlugIntf() override
    {
        for (unsigned i = 0; i < thread_loggers.size(); ++i)
            term_logger(i);
    }

    void thread_init() override;
    void thread_term() override;

    void instantiate(snort::Module*, snort::SnortConfig*, const char*) override;

    void init_logger(unsigned, Module*);
    void term_logger(unsigned);

public:
    const TraceLogApi* api;
    std::vector<TraceLoggerPlug*> thread_loggers;
};

class PlugInterface* TraceLoggerManager::get_interface(const snort::TraceLogApi* api)
{ return new TracePlugIntf(api); }

void TracePlugIntf::init_logger(unsigned idx, Module* mod)
{
    assert(thread_loggers.size() > idx);
    assert(!thread_loggers[idx]);
    TraceLoggerPlug* logger = api->ctor(mod, mod->get_name());
    logger->set_api(api);
    thread_loggers[idx] = logger;
}

void TracePlugIntf::term_logger(unsigned idx)
{
    assert(thread_loggers.size() > idx);

    if (thread_loggers[idx])
    {
        api->dtor(thread_loggers[idx]);
        thread_loggers[idx] = nullptr;
    }
}

// only instantiate for the main thread here
void TracePlugIntf::instantiate(Module* mod, SnortConfig*, const char*)
{
    thread_loggers.resize(ThreadConfig::get_instance_max()+1, nullptr);
    init_logger(0, mod);
}

// create logger instance for this thread
void TracePlugIntf::thread_init()
{
    unsigned idx = get_instance_id() + 1;
    Module* mod = PluginManager::get_module(api->base.name);
    init_logger(idx, mod);
}

// delete main thread logger or packet thread specific logger
void TracePlugIntf::thread_term()
{
    unsigned idx = get_instance_id() +1;
    assert(thread_loggers.size() > idx);
    term_logger(idx);
}

//--------------------------------------------------------------------------
// public methods
//--------------------------------------------------------------------------

TraceLoggerPlug* TraceLoggerManager::get_logger(const std::string& name)
{
    unsigned instance = in_main_thread() ? 0 : get_instance_id() + 1;
    TracePlugIntf* intf = (TracePlugIntf*)PluginManager::get_interface(name.c_str());
    return (intf and intf->thread_loggers.size() > instance) ? intf->thread_loggers[instance] : nullptr;
}

TraceLoggerPlug* TraceLoggerManager::set_logger(const std::string& name)
{
    unsigned instance = in_main_thread() ? 0 : get_instance_id() + 1;
    TracePlugIntf* intf = (TracePlugIntf*)PluginManager::get_interface(name.c_str());
    Module* mod = PluginManager::get_module(name.c_str());
    assert(intf and mod);
    intf->init_logger(instance, mod);
    return (intf->thread_loggers.size() > instance) ? intf->thread_loggers[instance] : nullptr;
}

void TraceLoggerManager::instantiate_default_loggers(TraceConfig* tc)
{
    for ( auto& s : tc->output_traces )
    {
        if ( get_logger(s) )
            continue;

        Module* mod = PluginManager::get_module(s.c_str());
        assert(mod);

        PluginManager::instantiate(mod, nullptr, nullptr);
    }
}

