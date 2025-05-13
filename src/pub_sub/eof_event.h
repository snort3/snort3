//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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

// eof_event.h author Maya Dagon <mdagon@cisco.com>

#ifndef EOF_EVENT_H
#define EOF_EVENT_H

#include "framework/data_bus.h"

namespace snort
{
class SO_PUBLIC EofEvent : public snort::DataEvent
{
public:
    EofEvent(const Flow* const flow) : f(flow) { }
    const std::string& get_history() const;
    const std::string& get_state() const;

private:
    const Flow* const f;
    mutable std::string history;
    mutable std::string state;
};
}

#endif
