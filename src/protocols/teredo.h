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
// teredo.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_TEREDO_H
#define PROTOCOLS_TEREDO_H

#include <cstdint>

namespace teredo
{
constexpr uint16_t TEREDO_PORT = 3544;
constexpr uint16_t INDICATOR_ORIGIN = 0x00;
constexpr uint16_t INDICATOR_ORIGIN_LEN = 8;
constexpr uint16_t INDICATOR_AUTH = 0x01;
constexpr uint16_t INDICATOR_AUTH_MIN_LEN = 13;
constexpr uint16_t MIN_HDR_LEN = 2;

inline bool is_teredo_port(uint16_t port)
{ return port == TEREDO_PORT; }
} // namespace teredo

#endif

