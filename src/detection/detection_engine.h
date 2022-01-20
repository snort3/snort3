//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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

// detection_engine_h author Russ Combs <rucombs@cisco.com>

#ifndef DETECTION_ENGINE_H
#define DETECTION_ENGINE_H

// DetectionEngine manages a detection context.  To detect a rebuilt
// packet (PDU), first call set_next_packet().  If rebuild is successful,
// then instantiate a new DetectionEngine to detect that packet.

#include "detection/detection_util.h"
#include "detection/ips_context.h"
#include "main/snort_types.h"

struct DataPointer;
struct Replacement;

namespace snort
{
struct Packet;
class Flow;
class IpsContext;
class IpsContextChain;
class IpsContextData;

class SO_PUBLIC DetectionEngine
{
public:
    DetectionEngine();
    ~DetectionEngine();

public:
    static void thread_init();
    static void thread_term();

    static void reset();

    static IpsContext* get_context();

    static Packet* get_current_packet();
    static Packet* get_current_wire_packet();
    static Packet* set_next_packet(Packet* parent = nullptr, Flow* flow = nullptr);
    static uint8_t* get_next_buffer(unsigned& max);

    static bool offload(Packet*);

    static void onload(Flow*);
    static void onload();
    static void idle();

    static void set_encode_packet(Packet*);
    static Packet* get_encode_packet();

    static void set_file_data(const DataPointer& dp);
    static DataPointer& get_file_data(IpsContext*);

    static uint8_t* get_buffer(unsigned& max);
    static struct DataBuffer& get_alt_buffer(Packet*);

    static void set_data(unsigned id, IpsContextData*);
    static IpsContextData* get_data(unsigned id);
    static IpsContextData* get_data(unsigned id, IpsContext*);

    static void add_replacement(const std::string&, unsigned);
    static bool get_replacement(std::string&, unsigned&);
    static void clear_replacement();

    static bool detect(Packet*, bool offload_ok = false);
    static bool inspect(Packet*);

    static int queue_event(const struct OptTreeNode*);
    static int queue_event(unsigned gid, unsigned sid);

    static void disable_all(Packet*);
    static bool all_disabled(Packet*);

    static void disable_content(Packet*);
    static void enable_content(Packet*);
    static bool content_enabled(Packet*);

    static IpsContext::ActiveRules get_detects(Packet*);
    static void set_detects(Packet*, IpsContext::ActiveRules);

    static void set_check_tags(bool enable = true);
    static bool get_check_tags();

    static void wait_for_context();

private:
    static struct SF_EVENTQ* get_event_queue();
    static bool do_offload(snort::Packet*);
    static void offload_thread(IpsContext*);
    static void complete(snort::Packet*);
    static void resume(snort::Packet*);
    static void resume_ready_suspends(const IpsContextChain&);

    static int log_events(Packet*);
    static void clear_events(Packet*);
    static void finish_inspect_with_latency(Packet*);
    static void finish_inspect(Packet*, bool inspected);
    static void finish_packet(Packet*, bool flow_deletion = false);

private:
    IpsContext* context;
};

static inline void set_file_data(const uint8_t* p, unsigned n)
{
    DataPointer dp { p, n };
    DetectionEngine::set_file_data(dp);
}

static inline void clear_file_data()
{ set_file_data(nullptr, 0); }

} // namespace snort
#endif

