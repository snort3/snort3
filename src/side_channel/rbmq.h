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

#ifndef RBMQ_H
#define RBMQ_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "sidechannel_define.h"

#ifndef SC_USE_DMQ

typedef struct _rbmq *RBMQ_Ptr;

RBMQ_Ptr RBMQ_Alloc(uint32_t msg_ring_entries, uint16_t msg_ring_header_size, uint32_t data_ring_size);
int RBMQ_ReserveMsg(RBMQ_Ptr mq, uint32_t length, void **hdr_ptr, uint8_t **msg_ptr, void **msg_handle);
int RBMQ_CommitReservedMsg(RBMQ_Ptr mq, void *msg_handle, uint32_t length, SCMQMsgFreeFunc msgFreeFunc);
int RBMQ_DiscardReservedMsg(RBMQ_Ptr mq, void *msg_handle);
int RBMQ_CommitExternalMsg(RBMQ_Ptr mq, const void *hdr, uint8_t *msg, uint32_t length, SCMQMsgFreeFunc msgFreeFunc);
int RBMQ_ReadMsg(RBMQ_Ptr mq, const void **hdr_ptr, const uint8_t **msg_ptr, uint32_t *length, void **msg_handle);
int RBMQ_AckMsg(RBMQ_Ptr mq, void *msg_handle);
int RBMQ_IsEmpty(RBMQ_Ptr mq);
void RBMQ_Stats(RBMQ_Ptr mq, const char *indent);

#endif /* !SC_USE_DMQ */

#endif /* RBMQ_H */
