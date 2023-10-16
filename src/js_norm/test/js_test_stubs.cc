//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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
// js_test_stubs.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "js_norm/js_enum.h"
#include "js_norm/js_norm_module.h"
#include "trace/trace_api.h"

THREAD_LOCAL const snort::Trace* js_trace = nullptr;
THREAD_LOCAL PegCount JSNormModule::peg_counts[jsn::PEG_COUNT_MAX] = {};

namespace snort
{
[[noreturn]] void FatalError(const char*, ...) { exit(EXIT_FAILURE); }

void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) { }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) { }

int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
Packet* DetectionEngine::get_current_packet() { return nullptr; }
}
