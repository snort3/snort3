//--------------------------------------------------------------------------
// Copyright (C) 2024-2026 Cisco and/or its affiliates. All rights reserved.
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
// pig_pen.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pig_pen.h"

#include <syslog.h>
#include <cassert>

#include "detection/detection_engine.h"
#include "log/log.h"
#include "main.h"
#include "main/process.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "managers/plugin_manager.h"
#include "profiler/profiler_impl.h"
#include "utils/stats.h"

using namespace snort;

//--------------------------------------------------------------------------
// inspector foo
//--------------------------------------------------------------------------

Module* PigPen::get_module(const char* s)
{ return PluginManager::get_module(s); }

//--------------------------------------------------------------------------
// inspector foo
//--------------------------------------------------------------------------

Inspector* PigPen::get_binder()
{ return InspectorManager::get_binder(); }

Inspector* PigPen::get_file_inspector(const SnortConfig* sc)
{ return InspectorManager::get_file_inspector(sc); }

Inspector* PigPen::acquire_file_inspector()
{ return InspectorManager::acquire_file_inspector(); }

Inspector* PigPen::get_service_inspector(const SnortProtocolId id)
{ return InspectorManager::get_service_inspector(id); }

Inspector* PigPen::get_service_inspector(const char* svc)
{ return InspectorManager::get_service_inspector(svc); }

Inspector* PigPen::get_inspector(const char* key, Module::Usage use)
{ return InspectorManager::get_inspector(key, use); }

Inspector* PigPen::get_new_inspector(const char* key)
{ return InspectorManager::get_new_inspector(key); }

Inspector* PigPen::get_old_inspector(const char* key, Module::Usage use)
{ return InspectorManager::get_old_inspector(key, use); }

void PigPen::release(Inspector* pi)
{ InspectorManager::release(pi); }

//--------------------------------------------------------------------------
// process foo
//--------------------------------------------------------------------------

bool PigPen::snort_started()
{ return main_snort_started(); }

bool PigPen::snort_is_reloading()
{ return Snort::is_reloading(); }

void PigPen::install_oops_handler()
{ ::install_oops_handler(); }

void PigPen::remove_oops_handler()
{ ::remove_oops_handler(); }

static unsigned s_opens = 0;

void PigPen::open_syslog()
{
    if ( ++s_opens == 1 )
        openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);
}

void PigPen::close_syslog()
{
    assert(s_opens > 0);

    if ( --s_opens == 0 )
        closelog();
}

//--------------------------------------------------------------------------
// detection foo
//--------------------------------------------------------------------------

bool PigPen::inspect_rebuilt(Packet* pdu)
{
    DetectionEngine de;
    return de.inspect(pdu);
}

//--------------------------------------------------------------------------
// stats foo
//--------------------------------------------------------------------------

uint64_t PigPen::get_packet_number()
{ return pc.analyzed_pkts; }

void PigPen::show_runtime_memory_stats()
{ Profiler::show_runtime_memory_stats(); }

//--------------------------------------------------------------------------
// log foo
//--------------------------------------------------------------------------

const char* PigPen::get_protocol_name(uint8_t ip_proto)
{ return ::get_protocol_name(ip_proto); }

//--------------------------------------------------------------------------
// log foo
//--------------------------------------------------------------------------

void PigPen::add_shutdown_hook(void (*f)())
{ Snort::add_shutdown_hook(f); }

