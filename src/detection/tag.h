//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef TAG_H
#define TAG_H

// rule option tag causes logging of some number of subsequent packets
// following an alert.  this module is use by the tag option to implement
// that functionality.  uses its own hash table.
//
// FIXIT-L convert tags to use flow instead of hash table.

#include <cstdint>

namespace snort
{
struct Packet;
}

class Event;
struct ListHead;
struct OptTreeNode;
struct SigInfo;

#define GID_TAG       2
#define TAG_LOG_PKT   1

#define TAG_SESSION   1
#define TAG_HOST      2
#define TAG_HOST_SRC  3
#define TAG_HOST_DST  4

#define TAG_METRIC_SECONDS    0x01
#define TAG_METRIC_PACKETS    0x02
#define TAG_METRIC_BYTES      0x04
#define TAG_METRIC_UNLIMITED  0x08
#define TAG_METRIC_SESSION    0x10

struct TagData
{
    int tag_type;       /* tag type (session/host) */
    int tag_metric;     /* (packets | seconds | bytes) units */
    int tag_direction;  /* source or dest, used for host tagging */

    uint32_t tag_seconds;    /* number of "seconds" units to tag for */
    uint32_t tag_packets;    /* number of "packets" units to tag for */
    uint32_t tag_bytes;      /* number of "type" units to tag for */
};

void InitTag();
void CleanupTag();
int CheckTagList(snort::Packet*, SigInfo&, ListHead*&, struct timeval&, uint32_t& id, const char*& action);
void SetTags(const snort::Packet*, const OptTreeNode*, uint16_t);

#endif

