//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

// cip_util.h author RA/Cisco

/* Description: Common utility functions. */

#ifndef CIP_UTIL_H
#define CIP_UTIL_H

#include <sys/types.h>  // For endian checks

#if __BYTE_ORDER == __LITTLE_ENDIAN

// Get 16-bit value from little endian byte array.
static inline uint16_t GetLEUint16(const uint8_t* pData)
{
    return (static_cast<uint16_t>(*(pData + 1) << 8)
           | static_cast<uint16_t>(*(pData + 0) << 0));
}

// Get 32-bit value from little endian byte array.
static inline uint32_t GetLEUint32(const uint8_t* pData)
{
    return (static_cast<uint32_t>(*(pData + 3) << 24)
           | static_cast<uint32_t>(*(pData + 2) << 16)
           | static_cast<uint32_t>(*(pData + 1) << 8)
           | static_cast<uint32_t>(*(pData + 0) << 0));
}

#else  // __BYTE_ORDER
#error "CIP Preprocessor is only supported on Little Endian."
#endif  // __BYTE_ORDER

#endif  /* CIP_UTIL_H */

