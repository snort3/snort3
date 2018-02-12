//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// pp_raw_buffer_iface.h author Joel Cornett <jocornet@cisco.com>

#ifndef PP_RAW_BUFFER_IFACE_H
#define PP_RAW_BUFFER_IFACE_H

#include <string>

#include "lua/lua_iface.h"

using RawBuffer = std::string;

inline const uint8_t* get_data(RawBuffer& rb)
{ return reinterpret_cast<const uint8_t*>(rb.data()); }

inline uint8_t* get_mutable_data(RawBuffer& rb)
{ return const_cast<uint8_t*>(get_data(rb)); }

extern const struct Lua::TypeInterface<RawBuffer> RawBufferIface;

#endif

