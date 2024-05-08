//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "log/log.h"
#include "main/process.h"
#include "main/snort.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler_impl.h"
#include "utils/stats.h"

using namespace snort;

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

Inspector* PigPen::get_inspector(const char* key, bool dflt_only, const SnortConfig* sc)
{ return InspectorManager::get_inspector(key, dflt_only, sc); }

Inspector* PigPen::get_inspector(const char* key, Module::Usage use, InspectorType type)
{ return InspectorManager::get_inspector(key, use, type); }

void PigPen::release(Inspector* pi)
{ InspectorManager::release(pi); }

//--------------------------------------------------------------------------
// process foo
//--------------------------------------------------------------------------

bool PigPen::snort_is_reloading()
{ return Snort::is_reloading(); }

void PigPen::install_oops_handler()
{ ::install_oops_handler(); }

void PigPen::remove_oops_handler()
{ ::remove_oops_handler(); }

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

