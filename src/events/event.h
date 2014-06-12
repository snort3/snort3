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

/*  D E F I N E S  ************************************************************/
#ifndef EVENT_H
#define EVENT_H

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "main/thread.h"

extern THREAD_LOCAL uint16_t event_id;

/* we must use fixed size of 32 bits, because on-disk
 * format of savefiles uses 32-bit tv_sec (and tv_usec)
 */
struct sf_timeval32
{
    uint32_t tv_sec;      /* seconds */
    uint32_t tv_usec;     /* microseconds */
};

typedef struct _Event
{
    const struct _SigInfo* sig_info;
    uint32_t event_id;        /* event ID */
    uint32_t event_reference; /* reference to other events that have gone off,
                                * such as in the case of tagged packets...
                                */
    struct sf_timeval32 ref_time;   /* reference time for the event reference */
    const char* alt_msg;
} Event;

void SetEvent(
    Event *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

#endif /* EVENT_H */

