//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
#include <string>

#include "main/snort_types.h"

struct OptTreeNode;

namespace snort
{
struct Packet;
}

class SO_PUBLIC Actions
{
public:
    using Type = uint8_t;
public:
    static std::string get_string(Type);
    static Type get_type(const char*);
    static Type get_max_types();
    static bool is_valid_action(Type);
    static std::string get_default_priorities(bool alert_before_pass = false);

    static void pass();
    static void log(snort::Packet*, const OptTreeNode*);
    static void alert(snort::Packet*, const OptTreeNode*);
};
#endif

