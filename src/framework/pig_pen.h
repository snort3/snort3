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
// pig_pen.h author Russ Combs <rucombs@cisco.com>

#ifndef FRAMEWORK_PIG_PEN_H
#define FRAMEWORK_PIG_PEN_H

#include "framework/inspector.h"
#include "framework/module.h"
#include "main/snort_types.h"
#include "target_based/snort_protocols.h"

struct PacketCount;

namespace snort
{
struct Packet;

struct SO_PUBLIC PigPen
{
    // module foo
    static Module* get_module(const char*);

    // inspector foo
    static Inspector* get_binder();

    static Inspector* get_file_inspector(const SnortConfig* = nullptr);
    static Inspector* acquire_file_inspector();

    static Inspector* get_service_inspector(const SnortProtocolId);
    static Inspector* get_service_inspector(const char*);

    // uses currently active policies only
    static Inspector* get_inspector(const char* key, Module::Usage);

    // only valid during swap (eg inspector dtor gets new instance)
    static Inspector* get_new_inspector(const char* key);

    // only valid during configure (eg inspector configure gets old instance)
    static Inspector* get_old_inspector(const char* key, Module::Usage);

    static void release(Inspector*);

    // process foo
    static bool snort_started();
    static bool snort_is_reloading();
    static void open_syslog();
    static void close_syslog();

    static void install_oops_handler();
    static void remove_oops_handler();

    // analyzer foo
    static bool inspect_rebuilt(Packet*);

    // stats foo
    static uint64_t get_packet_number();
    static void show_runtime_memory_stats();

    // log foo
    static const char* get_protocol_name(uint8_t ip_proto);

    // shutdown foo
    static void add_shutdown_hook(void (*func)());
};

}
#endif

