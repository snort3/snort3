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

#include "rbmq.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SIDE_CHANNEL
#include <assert.h>
#include <errno.h>
#include "util.h"

#ifndef SC_USE_DMQ
#define RBMQ_MSG_FLAG_EXTERNAL  0x01

enum {
    RBMQ_MSG_STATE_UNUSED = 0,
    RBMQ_MSG_STATE_RESERVED,
    RBMQ_MSG_STATE_COMMITTED,
    RBMQ_MSG_STATE_READ,
    RBMQ_MSG_STATE_ACKED,
    RBMQ_MSG_STATE_DISCARDED
};

typedef struct _rbmq_msg
{
    uint32_t length;
    uint8_t flags;
    uint8_t state;
    uint8_t *data;
    SCMQMsgFreeFunc msgFreeFunc;
} RBMQ_Msg;

typedef struct _rmbq_internal_data_hdr
{
    uint32_t msg_index;
    uint32_t prev_offset;
} RBMQ_InternalDataHdr;

typedef struct _rbmq_msg_ring
{
    RBMQ_Msg *msgs;
    uint8_t *headers;
    uint32_t last_reserved;
    uint32_t last_read;
    uint32_t last_acked;
    uint32_t entries;
    uint16_t header_size;
} RBMQ_MsgRing;

typedef struct _rbmq_data_ring
{
    uint8_t *data;
    uint32_t read_offset;
    uint32_t write_offset;
    uint32_t size;
} RBMQ_DataRing;

typedef struct _rbmq
{
    RBMQ_MsgRing msg_ring;
    RBMQ_DataRing data_ring;
} RBMQ;

static inline uint32_t IncrementMessageIndex(RBMQ *mq, uint32_t index)
{
    return (++index == mq->msg_ring.entries) ? 0 : index;
}

static inline uint32_t DecrementMessageIndex(RBMQ *mq, uint32_t index)
{
    return (index == 0) ? (mq->msg_ring.entries - 1) : (index - 1);
}

/* Returns 0 if the message handle is within bounds for the control ring, non-zero otherwise. */
static inline int ValidateMsgHandle(RBMQ *mq, void *msg_handle)
{
    return (msg_handle < (void *)(&mq->msg_ring.msgs[0]) || msg_handle > (void *)(&mq->msg_ring.msgs[mq->msg_ring.entries - 1]));
}

RBMQ *RBMQ_Alloc(uint32_t msg_ring_entries, uint16_t msg_ring_header_size, uint32_t data_ring_size)
{
    RBMQ *mq;

    mq = SnortAlloc(sizeof(RBMQ));
    memset(mq, 0, sizeof(RBMQ));

    /* Initialize the control ring. */
    mq->msg_ring.msgs = SnortAlloc(msg_ring_entries * sizeof(RBMQ_Msg));
    mq->msg_ring.headers = SnortAlloc(msg_ring_entries * msg_ring_header_size);
    mq->msg_ring.entries = msg_ring_entries;
    mq->msg_ring.header_size = msg_ring_header_size;
    memset(mq->msg_ring.msgs, 0, mq->msg_ring.entries * sizeof(RBMQ_Msg));
    mq->msg_ring.last_reserved = 0;
    mq->msg_ring.last_read = 0;
    mq->msg_ring.last_acked = 0;

    /* Initialize the data ring. */
    mq->data_ring.data = SnortAlloc(data_ring_size);
    mq->data_ring.size = data_ring_size;
    memset(mq->data_ring.data, 0, mq->data_ring.size);

    return mq;
}

void RBMQ_Destroy(RBMQ *mq)
{
    RBMQ_Msg *msg_info;
    uint32_t idx;

    /* Free the data for any unprocessed messages. */
    idx = mq->msg_ring.last_acked;
    while (idx != mq->msg_ring.last_reserved)
    {
        idx++;
        if (idx == mq->msg_ring.entries)
            idx = 0;
        msg_info = &mq->msg_ring.msgs[idx];
        if (msg_info->msgFreeFunc)
            msg_info->msgFreeFunc(msg_info->data);
    }
    
    /* Release all of our resources. */
    free(mq->data_ring.data);
    free(mq->msg_ring.msgs);
}

int RBMQ_ReserveMsg(RBMQ *mq, uint32_t length, void **hdr_ptr, uint8_t **msg_ptr, void **msg_handle)
{
    RBMQ_InternalDataHdr *idh;
    RBMQ_Msg *msg_info;
    uint32_t msg_index, msg_len, start_offset;

    /* Find the next entry in the message ring to reserve. */
    msg_index = IncrementMessageIndex(mq, mq->msg_ring.last_reserved);
    msg_info = &mq->msg_ring.msgs[msg_index];

    /* Bail if the entry is in use. */
    if (msg_info->state != RBMQ_MSG_STATE_UNUSED)
        return -ENOMEM;

    /* Make sure that we can reserve the requested space in the data ring. */
    msg_len = length + sizeof(RBMQ_InternalDataHdr);
    if (mq->data_ring.write_offset < mq->data_ring.read_offset)
    {
        if ((mq->data_ring.read_offset - mq->data_ring.write_offset) < msg_len)
            return -ENOMEM;
        start_offset = mq->data_ring.write_offset;
    }
    else if ((mq->data_ring.size - mq->data_ring.write_offset) < msg_len)
    {
        if (mq->data_ring.read_offset < msg_len)
            return -ENOMEM;
        start_offset = 0;
    }
    else
        start_offset = mq->data_ring.write_offset;

    idh = (RBMQ_InternalDataHdr *) (mq->data_ring.data + start_offset);
    idh->msg_index = msg_index;
    idh->prev_offset = mq->data_ring.write_offset;

    /* Update the write offset in the data ring, wrapping as necessary. */
    mq->data_ring.write_offset = start_offset + msg_len;
    if (mq->data_ring.write_offset == mq->data_ring.size)
        mq->data_ring.write_offset = 0;

    msg_info->length = length;
    /* Type is filled in during the commit. */
    msg_info->flags = 0;
    msg_info->state = RBMQ_MSG_STATE_RESERVED;
    msg_info->data = (uint8_t *) idh + sizeof(RBMQ_InternalDataHdr);
    msg_info->msgFreeFunc = NULL;

    /* Update the last reservation index in the control ring. */
    mq->msg_ring.last_reserved = msg_index;

    if (mq->msg_ring.header_size)
        *hdr_ptr = mq->msg_ring.headers + (msg_index * mq->msg_ring.header_size);
    else
        *hdr_ptr = NULL;
    *msg_ptr = msg_info->data;
    *msg_handle = (void *) msg_info;

    return 0;
}

int RBMQ_CommitReservedMsg(RBMQ *mq, void *msg_handle, uint32_t length, SCMQMsgFreeFunc msgFreeFunc)
{
    RBMQ_Msg *msg_info;

    if (ValidateMsgHandle(mq, msg_handle))
        return -EINVAL;

    msg_info = (RBMQ_Msg *) msg_handle;

    /* Sanity checks... */
    if (msg_info->state != RBMQ_MSG_STATE_RESERVED)
    {
        ErrorMessage("%s: Attempted to commit an unreserved message! (State: %hhu)\n", __FUNCTION__, msg_info->state);
        return -EINVAL;
    }

    if (length > msg_info->length)
    {
        ErrorMessage("%s: Attempted to commit illegally enlarged message! (%u vs %u)\n", __FUNCTION__, length, msg_info->length);
        return -EINVAL;
    }

    /* If the committed length is less than the reserved length and it was the last message reserved,
        truncate the internal data ring usage. */
    if (length < msg_info->length && msg_info == &mq->msg_ring.msgs[mq->msg_ring.last_reserved])
    {
        if (mq->data_ring.write_offset != 0)
            mq->data_ring.write_offset -= (msg_info->length - length);
        else
            mq->data_ring.write_offset = mq->data_ring.size - (msg_info->length - length);
        msg_info->length = length;
    }

    msg_info->state = RBMQ_MSG_STATE_COMMITTED;
    msg_info->msgFreeFunc = msgFreeFunc;

    return 0;
}

int RBMQ_DiscardReservedMsg(RBMQ *mq, void *msg_handle)
{
    RBMQ_InternalDataHdr *idh;
    RBMQ_Msg *msg_info;
    uint32_t idx;

    if (ValidateMsgHandle(mq, msg_handle))
        return -EINVAL;

    msg_info = (RBMQ_Msg *) msg_handle;

    /* Sanity checks... */
    if (msg_info->state != RBMQ_MSG_STATE_RESERVED)
    {
        ErrorMessage("%s: Attempted to discard an unreserved message! (State: %hhu)\n", __FUNCTION__, msg_info->state);
        return -EINVAL;
    }

    msg_info->state = RBMQ_MSG_STATE_DISCARDED;

    /* Working backward from the last entry reserved (in order), release discarded messages as allowed. 
        Any discarded messages that we can't release here will have to wait until something gets ACK'd. */
    idx = mq->msg_ring.last_reserved;
    msg_info = &mq->msg_ring.msgs[idx];
    while (msg_info->state == RBMQ_MSG_STATE_DISCARDED)
    {
        /* Clean up the data ring state if this was internally allocated.  Only internally allocated
            messages can be discarded, so this should be safe. */
        idh = (RBMQ_InternalDataHdr *) (msg_info->data - sizeof(RBMQ_InternalDataHdr));
        mq->data_ring.write_offset = idh->prev_offset;

        /* Reset the state to unused so that it can be reserved again. */
        msg_info->state = RBMQ_MSG_STATE_UNUSED;

        /* Finally, update the last reserved index. */
        idx = DecrementMessageIndex(mq, idx);
        mq->msg_ring.last_reserved = idx;
        msg_info = &mq->msg_ring.msgs[idx];
    }

    return 0;
}

int RBMQ_CommitExternalMsg(RBMQ *mq, const void *hdr, uint8_t *msg, uint32_t length, SCMQMsgFreeFunc msgFreeFunc)
{
    RBMQ_Msg *msg_info;
    uint32_t idx;

    /* V Reserve and commit the message all in one step. V */

    /* Find the next entry in the message ring to reserve. */
    idx = IncrementMessageIndex(mq, mq->msg_ring.last_reserved);
    msg_info = &mq->msg_ring.msgs[idx];

    /* Bail if the entry is in use. */
    if (msg_info->state != RBMQ_MSG_STATE_UNUSED)
        return -ENOMEM;

    /* Require a header if there is a header size specified for the control ring and copy it over. */
    if (mq->msg_ring.header_size)
    {
        if (!hdr)
            return -EINVAL;
        memcpy(mq->msg_ring.headers + (idx * mq->msg_ring.header_size), hdr, mq->msg_ring.header_size);
    }

    msg_info->length = length;
    msg_info->flags = RBMQ_MSG_FLAG_EXTERNAL;
    msg_info->state = RBMQ_MSG_STATE_COMMITTED;
    msg_info->data = msg;
    msg_info->msgFreeFunc = msgFreeFunc;

    /* Update the last reservation index in the control ring. */
    mq->msg_ring.last_reserved = idx;

    return 0;
}

int RBMQ_ReadMsg(RBMQ *mq, const void **hdr_ptr, const uint8_t **msg_ptr, uint32_t *length, void **msg_handle)
{
    RBMQ_Msg *msg_info;
    uint32_t idx;

    /* Find the next entry in the message ring to read. */
    idx = IncrementMessageIndex(mq, mq->msg_ring.last_read);
    msg_info = &mq->msg_ring.msgs[idx];

    /* Skip over discarded messages -- the next ACK should clear them out. */
    while (msg_info->state == RBMQ_MSG_STATE_DISCARDED)
    {
        mq->msg_ring.last_read = idx;
        idx = IncrementMessageIndex(mq, idx);
        msg_info = &mq->msg_ring.msgs[idx];
    }

    /* Return an error if there is not a committed entry ready to be read. */
    if (msg_info->state != RBMQ_MSG_STATE_COMMITTED)
        return -ENOENT;

    if (mq->msg_ring.header_size)
        *hdr_ptr = mq->msg_ring.headers + (idx * mq->msg_ring.header_size);
    else
        *hdr_ptr = NULL;
    *msg_ptr = msg_info->data;
    *length = msg_info->length;
    *msg_handle = msg_info;

    msg_info->state = RBMQ_MSG_STATE_READ;
    mq->msg_ring.last_read = idx;

    return 0;
}

int RBMQ_AckMsg(RBMQ *mq, void *msg_handle)
{
    RBMQ_Msg *msg_info;
    uint32_t idx;

    /* Sanity checking... */
    if (ValidateMsgHandle(mq, msg_handle))
        return -EINVAL;

    msg_info = (RBMQ_Msg *) msg_handle;
    if (msg_info->state != RBMQ_MSG_STATE_READ)
    {
        ErrorMessage("%s: Attempted to ACK an unread message! (State: %hhu)\n", __FUNCTION__, msg_info->state);
        return -EINVAL;
    }

    /* Call the user defined free function to release the message data if it exists. */
    if (msg_info->data && msg_info->msgFreeFunc)
        msg_info->msgFreeFunc(msg_info->data);

    msg_info->state = RBMQ_MSG_STATE_ACKED;

    /* Working forward from the last entry ACK'd (in order), release ACK'd and discarded messages as allowed. */
    do {
        idx = IncrementMessageIndex(mq, mq->msg_ring.last_acked);
        msg_info = &mq->msg_ring.msgs[idx];
        if (msg_info->state != RBMQ_MSG_STATE_ACKED && msg_info->state != RBMQ_MSG_STATE_DISCARDED)
            break;

        /* Clean up the data ring state if this was internally allocated.  We are guaranteed that internal
            allocations will be sequential in relation to sequential control entries.*/
        if (!(msg_info->flags & RBMQ_MSG_FLAG_EXTERNAL))
            mq->data_ring.read_offset = msg_info->data + msg_info->length - mq->data_ring.data;

        /* Reset the state to unused so it can be reserved again. */
        msg_info->state = RBMQ_MSG_STATE_UNUSED;

        /* Finally, update the last ACK'd index to accurately represent how far processing has gotten. */
        mq->msg_ring.last_acked = idx;
    } while (mq->msg_ring.last_acked != mq->msg_ring.last_read);

    return 0;
}

int RBMQ_IsEmpty(RBMQ *mq)
{
    RBMQ_Msg *msg_info;
    uint32_t idx;

    /* Find the next entry in the message ring to read and return true if it's not committed. */
    idx = IncrementMessageIndex(mq, mq->msg_ring.last_read);
    msg_info = &mq->msg_ring.msgs[idx];

    return (msg_info->state != RBMQ_MSG_STATE_COMMITTED);
}

void RBMQ_Stats(RBMQ_Ptr mq, const char *indent)
{
}

#endif /* !SC_USE_DMQ */

#endif /* SIDE_CHANNEL */
