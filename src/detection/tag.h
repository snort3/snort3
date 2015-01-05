/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef TAG_H
#define TAG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdint>

struct Packet;
struct OptTreeNode;
struct Event;


#define TAG_SESSION   1
#define TAG_HOST      2
#define TAG_HOST_SRC  3
#define TAG_HOST_DST  4

#define TAG_METRIC_SECONDS    0x1
#define TAG_METRIC_PACKETS    0x2
#define TAG_METRIC_BYTES      0x4
#define TAG_METRIC_UNLIMITED  0x8


void InitTag(void);
void CleanupTag(void);
int CheckTagList(Packet *, Event *);
void SetTags(Packet *, OptTreeNode *, uint16_t);
void TagCacheReset(void);

#endif /* TAG_H */
