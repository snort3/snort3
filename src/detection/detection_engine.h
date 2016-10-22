//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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
// packet (PDU), first call set_packet().  If rebuild is successful,
// then instantiate a new DetectionContext() to detect that packet.

#include "actions/actions.h"
#include "main/snort_types.h"

class IpsContext;
class IpsContextData;
struct Packet;

class SO_PUBLIC DetectionEngine
{
public:
    DetectionEngine();
    ~DetectionEngine();

    Packet* get_packet();

public:
    static IpsContext* get_context();

    static Packet* get_current_packet();
    static Packet* set_packet();
    static void clear_packet();

    static class MpseStash* get_stash();
    static uint8_t* get_buffer(unsigned& max);

    static void set_data(unsigned id, IpsContextData*);
    static IpsContextData* get_data(unsigned id);

    static bool detect(Packet*);
    static void inspect(Packet*);

    static int queue_event(const struct OptTreeNode*);
    static int queue_event(unsigned gid, unsigned sid, RuleType = RULE_TYPE__NONE);

    static int log_events(struct Packet*);

    static void reset();
    static void reset_counts();

    enum ActiveRules
    { NONE, NON_CONTENT, CONTENT };

    static ActiveRules get_detects();
    static void set_detects(ActiveRules);

    static void disable_content();
    static void disable_all();

    static void enable_content()
    { set_detects(CONTENT); }

    static bool content_enabled()
    { return get_detects() == CONTENT; }

private:
    static struct SF_EVENTQ* get_event_queue();
};

#endif

