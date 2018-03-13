//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifndef ACTIONS_H
#define ACTIONS_H

// Define action types and provide hooks to apply a given action to a packet

#include <cstdint>

#include "main/snort_types.h"

struct OptTreeNode;

namespace snort
{
struct Packet;

class SO_PUBLIC Actions
{
public:
    // FIXIT-L if Type is changed, RateFilterModule and type in actions.cc must be updated
    enum Type
    { NONE = 0, LOG, PASS, ALERT, DROP, BLOCK, RESET, MAX };

    static const char* get_string(Type);
    static Type get_type(const char*);

    static void execute(Type, struct Packet*, const struct OptTreeNode*,
        uint16_t event_id);

    static void apply(Type, struct Packet*);

    static inline bool is_pass(Type a)
    { return ( a == PASS ); }
};
}
#endif

