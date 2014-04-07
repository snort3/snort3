/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2012-2013 Sourcefire, Inc.
 *
 * Author: Michael Altizer <maltizer@sourcefire.com>
 *
 */

#ifndef SIDECHANNEL_DEFINE_H
#define SIDECHANNEL_DEFINE_H

#include <stdint.h>

#define SC_USE_DMQ 1

/* You get 16 bits worth of types.  Use them wisely. */
enum
{
    SC_MSG_TYPE_NONE = 0,
    SC_MSG_TYPE_FLOW_STATE_TRACKING,
    SC_MSG_TYPE_ANY = 0xFFFF
};

typedef struct _SC_MESSAGE_HEADER
{
    uint16_t type;
    uint64_t timestamp;
} SCMsgHdr;

typedef struct _SC_MESSAGE_QUEUE_NODE *SCMessageQueueNodePtr;

typedef void (*SCMQMsgFreeFunc)(void *);

typedef int (*SCMConfigFunc)(char *);
typedef int (*SCMInitFunc)(void);
typedef int (*SCMPostInitFunc)(void);
typedef void (*SCMStatsFunc)(int exiting);
typedef void (*SCMIdleFunc)(void);
typedef int (*SCMProcessMsgFunc)(SCMsgHdr *hdr, const uint8_t *msg, uint32_t length);
typedef void (*SCMShutdownFunc)(void);

typedef struct _SCM_FUNCTION_BUNDLE {
    SCMConfigFunc configFunc;
    SCMInitFunc initFunc;
    SCMPostInitFunc postInitFunc;
    SCMIdleFunc idleFunc;
    SCMStatsFunc statsFunc;
    SCMShutdownFunc shutdownFunc;
} SCMFunctionBundle;

#endif /* SIDECHANNEL_DEFINE_H */
