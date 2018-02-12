//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// dcerpc.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dcerpc.h"

#include <arpa/inet.h>

#define min(x,y) ((x)<(y) ? (x) : (y))

#define DCERPC_LE_FLAG  0x10

#pragma pack(1)

struct DCERPCHeader
{
    uint8_t version;
    uint8_t minor_version;
    uint8_t type;
    uint8_t flags;
    uint8_t drep[4];
    uint16_t frag_length;
    uint16_t auth_length;
    uint32_t id;
};

#pragma pack()

// FIXIT-L - see if this can be moved to a file of common functions
int dcerpc_validate(const uint8_t* data, int size)
{
    const DCERPCHeader* hdr;
    uint16_t len;

    if (size < (int)sizeof(DCERPCHeader))
        return -1;
    hdr = (const DCERPCHeader*)data;
    if (hdr->version != 5)
        return -1;
    if (hdr->minor_version > 1)
        return -1;
    if (hdr->type > 19)
        return -1;
    if (hdr->drep[0] & DCERPC_LE_FLAG)
    {
        len = hdr->frag_length;
    }
    else
    {
        len = ntohs(hdr->frag_length);
    }
    if (len < sizeof(DCERPCHeader))
        return -1;
    if (size < len)
        return -1;
    return (int)len;
}

