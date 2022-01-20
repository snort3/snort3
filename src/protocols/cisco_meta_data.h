//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// cisco_meta_data.h author Michael Altizer <mialtize@cisco.com>

#ifndef PROTOCOLS_CISCO_META_DATA_H
#define PROTOCOLS_CISCO_META_DATA_H

#include <arpa/inet.h>

namespace snort
{
namespace cisco_meta_data
{
struct CiscoMetaDataHdr
{
    uint8_t version;        // MetaData header version
    uint8_t length;         // Header size in quadwords
    uint16_t opt_len_type;  // 3-bit length + 13-bit type
    uint16_t sgt;           // Security Group Tag (anything but 0xFFFF)
    uint16_t ether_type;    // Ethertype for following layer

    inline uint16_t sgt_val() const
    { return ntohs(sgt); }
};
}
}

#endif
