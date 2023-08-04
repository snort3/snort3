//--------------------------------------------------------------------------
// Copyright (C) 2023-2023 Cisco and/or its affiliates. All rights reserved.
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
// dce_curse.h author Maya Dagon <mdagon@cisco.com>
// Refactored from curses.h

#ifndef DCE_CURSE_H
#define DCE_CURSE_H

// DCE curse helps determine if the traffic being processed is DCERPC

#include <cstdint>

enum DCE_State
{
    DCE_STATE__0 = 0,
    DCE_STATE__1,
    DCE_STATE__2,
    DCE_STATE__3,
    DCE_STATE__4,
    DCE_STATE__5,
    DCE_STATE__6,
    DCE_STATE__7,
    DCE_STATE__8,
    DCE_STATE__9,
    DCE_STATE__10
};

class DceTracker
{
public:  
    DCE_State state = DCE_State::DCE_STATE__0;
    uint32_t helper;
};

#endif
