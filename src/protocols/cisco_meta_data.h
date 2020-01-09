//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// cisco_meta_data.h author Sunirmal Mukherjee <sunimukh@cisco.com>

#ifndef PROTOCOLS_CISCO_META_DATA_H
#define PROTOCOLS_CISCO_META_DATA_H

#include <arpa/inet.h>

namespace snort
{
namespace cisco_meta_data
{
struct CiscoMetaDataHdr
{
    uint8_t version; // This must be 1
    uint8_t length; //This is the header size in bytes / 8
};

struct CiscoMetaDataOpt
{
    uint16_t opt_len_type;  // 3-bit length + 13-bit type. Type must be 1
    uint16_t sgt;           // Can be any value except 0xFFFF

    inline uint16_t sgt_val() const
    { return ntohs(sgt); }
};
}
}

#endif
