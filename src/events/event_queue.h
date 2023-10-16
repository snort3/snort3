//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

#ifndef EVENT_QUEUE_H
#define EVENT_QUEUE_H

#include "main/snort_types.h"

#define SNORT_EVENTQ_PRIORITY    1
#define SNORT_EVENTQ_CONTENT_LEN 2

struct EventQueueConfig
{
    unsigned max_events;
    unsigned log_events;
    int order;
    int process_all_events;
};

struct EventNode
{
    const struct OptTreeNode* otn;
    const struct RuleTreeNode* rtn;
};

EventQueueConfig* EventQueueConfigNew();
void EventQueueConfigFree(EventQueueConfig*);

#endif

