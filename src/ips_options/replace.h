/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

#ifndef REPLACE_H
#define REPLACE_H

#include <assert.h>
#include "ips_content.h"
#include "main/thread.h"

void PayloadReplaceInit(PatternMatchData*, char*, OptTreeNode*);

void Replace_ResetQueue(void);
void Replace_QueueChange(PatternMatchData*);
void Replace_ModifyPacket(Packet*);

static inline void Replace_ResetOffset(PatternMatchData* pmd)
{
    if ( pmd->replace_depth )
        pmd->replace_depth[get_instance_id()] = -1;
}

static inline void Replace_StoreOffset(PatternMatchData* pmd, int detect_depth)
{
    if ( pmd->replace_depth )
        pmd->replace_depth[get_instance_id()] = detect_depth;
}

static inline int Replace_OffsetStored(PatternMatchData* pmd)
{
    if ( pmd->replace_depth )
        return pmd->replace_depth[get_instance_id()] >= 0;

    return 0;
}

#endif

