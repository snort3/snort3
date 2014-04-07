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

#include "dmq.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SIDE_CHANNEL
#include <errno.h>
#include "util.h"

#ifdef SC_USE_DMQ
#define DMQ_NODE_FLAG_EXTERNAL  0x01

typedef struct _dmq_node
{
    struct _dmq_node *next;
    uint32_t length;
    uint32_t allocated;
    uint8_t flags;
    uint8_t *data;
    SCMQMsgFreeFunc msgFreeFunc;
} DMQ_Node;

typedef struct _dmq
{
    DMQ_Node *head;
    DMQ_Node *tail;
    DMQ_Node *free_list;
    uint16_t user_header_size;
    uint32_t length;
    uint32_t internal_size;
    uint32_t external_size;
    uint32_t overhead_size;
    uint32_t length_limit;
    uint32_t internal_size_limit;
    uint32_t max_length;
    uint32_t max_internal_size;
} DMQ;

DMQ *DMQ_Alloc(uint32_t msg_ring_entries, uint16_t msg_ring_header_size, uint32_t data_ring_size)
{
    DMQ_Node *node;
    DMQ *mq;
    uint32_t i;

    mq = (DMQ*)SnortAlloc(sizeof(DMQ));

    mq->head = mq->tail = mq->free_list = NULL;

    mq->user_header_size = msg_ring_header_size;

    mq->length = 0;
    mq->internal_size = 0;
    mq->external_size = 0;
    mq->overhead_size = 0;

    mq->length_limit = msg_ring_entries;
    mq->internal_size_limit = data_ring_size;

    /* Preallocate the Queue nodes. */
    for (i = 0; i < mq->length_limit; i++)
    {
        node = (DMQ_Node*)SnortAlloc(sizeof(DMQ_Node) + mq->user_header_size);
        node->next = mq->free_list;
        mq->free_list = node;
        mq->overhead_size += sizeof(DMQ_Node) + mq->user_header_size;
    }

    LogMessage("%s: Preallocated %u bytes for queue node structures.\n", __FUNCTION__, mq->overhead_size);

    return mq;
}

int DMQ_ReserveMsg(DMQ *mq, uint32_t length, void **hdr_ptr, uint8_t **msg_ptr, void **msg_handle)
{
    DMQ_Node *node;

    if (!mq->free_list)
        return -ENOSPC;

    if (length > (mq->internal_size_limit - mq->internal_size))
        return -ENOMEM;

    node = mq->free_list;
    mq->free_list = node->next;

    node->next = NULL;
    node->length = length;
    node->allocated = length;
    node->flags = 0;
    node->data = (uint8_t*)SnortAlloc(length);
    node->msgFreeFunc = NULL;

    *hdr_ptr = (uint8_t *) node + sizeof(DMQ_Node);
    *msg_ptr = node->data;
    *msg_handle = (void *) node;

    mq->internal_size += length;
    if (mq->internal_size > mq->max_internal_size)
        mq->max_internal_size = mq->internal_size;

    return 0;
}

int DMQ_CommitReservedMsg(DMQ *mq, void *msg_handle, uint32_t length, SCMQMsgFreeFunc msgFreeFunc)
{
    DMQ_Node *node = (DMQ_Node *) msg_handle;

    if (!node)
        return -EINVAL;

    if (length > node->length)
    {
        ErrorMessage("%s: Attempted to commit illegally enlarged message! (%u vs %u)\n", __FUNCTION__, length, node->length);
        return -EINVAL;
    }

    node->length = length;

    if (mq->head)
    {
        mq->tail->next = node;
        mq->tail = node;
    }
    else
        mq->head = mq->tail = node;

    mq->length++;
    if (mq->length > mq->max_length)
        mq->max_length = mq->length;

    return 0;
}

static void DMQ_DestroyNode(DMQ *mq, DMQ_Node *node)
{
    if (node->msgFreeFunc)
        node->msgFreeFunc(node->data);

    if (!(node->flags & DMQ_NODE_FLAG_EXTERNAL))
    {
        mq->internal_size -= node->allocated;
        free(node->data);
    }
    else
        mq->external_size -= node->length;

    node->next = mq->free_list;
    mq->free_list = node;
}

int DMQ_DiscardReservedMsg(DMQ *mq, void *msg_handle)
{
    DMQ_Node *node = (DMQ_Node *) msg_handle;

    if (!node)
        return -EINVAL;

    DMQ_DestroyNode(mq, node);

    return 0;
}

int DMQ_CommitExternalMsg(DMQ *mq, const void *hdr, uint8_t *msg, uint32_t length, SCMQMsgFreeFunc msgFreeFunc)
{
    DMQ_Node *node;

    if (!mq->free_list)
        return -ENOMEM;

    node = mq->free_list;
    mq->free_list = node->next;

    if (mq->user_header_size)
    {
        if (!hdr)
            return -EINVAL;
        memcpy((uint8_t *) node + sizeof(DMQ_Node), hdr, mq->user_header_size);
    }

    node->next = NULL;
    node->length = length;
    node->allocated = 0;
    node->flags = DMQ_NODE_FLAG_EXTERNAL;
    node->data = msg;
    node->msgFreeFunc = msgFreeFunc;

    if (mq->head)
    {
        mq->tail->next = node;
        mq->tail = node;
    }
    else
        mq->head = mq->tail = node;

    mq->length++;
    if (mq->length > mq->max_length)
        mq->max_length = mq->length;

    mq->external_size += length;

    return 0;
}

int DMQ_ReadMsg(DMQ *mq, const void **hdr_ptr, const uint8_t **msg_ptr, uint32_t *length, void **msg_handle)
{
    DMQ_Node *node;

    if (!mq->head)
        return -ENOENT;

    node = mq->head;
    mq->head = node->next;
    if (!mq->head)
        mq->tail = NULL;
    node->next = NULL;

    if (mq->user_header_size)
        *hdr_ptr = (uint8_t *) node + sizeof(DMQ_Node);
    else
        *hdr_ptr = NULL;
    *msg_ptr = node->data;
    *length = node->length;
    *msg_handle = (void *) node;

    mq->length--;

    return 0;
}

int DMQ_AckMsg(DMQ *mq, void *msg_handle)
{
    DMQ_Node *node = (DMQ_Node *) msg_handle;

    if (!node)
        return -EINVAL;

    DMQ_DestroyNode(mq, node);

    return 0;
}

int DMQ_IsEmpty(DMQ *mq)
{
    return (mq->head == NULL);
}

void DMQ_Stats(DMQ_Ptr mq, const char *indent)
{
    LogMessage("%s  Length: %u (%u max)\n", indent, mq->length, mq->max_length);
    LogMessage("%s  Size: %u internal (%u max), %u external, %u overhead\n",
                indent, mq->internal_size, mq->max_internal_size, mq->external_size, mq->overhead_size);
}

#endif /* SC_USE_DMQ */

#endif /* SIDE_CHANNEL */
