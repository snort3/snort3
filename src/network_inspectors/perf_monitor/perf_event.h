//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
/*
**  Marc Norton <mnorton@sourcefire.com>
**  Dan Roelker <droelker@sourcefire.com>
**
**  NOTES
**  5.28.02 - Initial Source Code. Norton/Roelker
*/

#ifndef PERF_EVENT_H
#define PERF_EVENT_H

#include "main/snort_types.h"

/* Raw event counters */
typedef struct _SFEVENT
{
    uint64_t NQEvents;
    uint64_t QEvents;

    uint64_t TotalEvents;
} SFEVENT;

/* Processed event counters */
typedef struct _SFEVENT_STATS
{
    uint64_t NQEvents;
    uint64_t QEvents;

    uint64_t TotalEvents;

    double NQPercent;
    double QPercent;
}  SFEVENT_STATS;

/*
**  These functions are for interfacing with the main
**  perf module.
*/
int InitEventStats(SFEVENT* sfEvent);
int ProcessEventStats(SFEVENT* sfEvent);

/*
**  These functions are external for updating the
**  SFEVENT structure.
*/
int UpdateNQEvents(SFEVENT*);
int UpdateQEvents(SFEVENT*);

#endif

