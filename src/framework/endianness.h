//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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
//endianness.h author Maya Dagon <mdagon@cisco.com>

#ifndef ENDIANNESS_H
#define ENDIANNESS_H

#include "main/snort_types.h"

namespace snort
{
class SO_PUBLIC Endianness
{
public:
    Endianness() = default;
    virtual ~Endianness() = default;
    virtual bool get_offset_endianness(int32_t offset, uint8_t& endian) = 0;
};
}
#endif

