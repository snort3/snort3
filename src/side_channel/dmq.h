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

#ifndef DMQ_H
#define DMQ_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "sidechannel_define.h"

#ifdef SC_USE_DMQ

typedef struct _dmq *DMQ_Ptr;

DMQ_Ptr DMQ_Alloc(uint32_t msg_ring_entries, uint16_t msg_ring_header_size, uint32_t data_ring_size);
int DMQ_ReserveMsg(DMQ_Ptr mq, uint32_t length, void **hdr_ptr, uint8_t **msg_ptr, void **msg_handle);
int DMQ_CommitReservedMsg(DMQ_Ptr mq, void *msg_handle, uint32_t length, SCMQMsgFreeFunc msgFreeFunc);
int DMQ_DiscardReservedMsg(DMQ_Ptr mq, void *msg_handle);
int DMQ_CommitExternalMsg(DMQ_Ptr mq, const void *hdr, uint8_t *msg, uint32_t length, SCMQMsgFreeFunc msgFreeFunc);
int DMQ_ReadMsg(DMQ_Ptr mq, const void **hdr_ptr, const uint8_t **msg_ptr, uint32_t *length, void **msg_handle);
int DMQ_AckMsg(DMQ_Ptr mq, void *msg_handle);
int DMQ_IsEmpty(DMQ_Ptr mq);
void DMQ_Stats(DMQ_Ptr mq, const char *indent);

#endif /* SC_USE_DMQ */

#endif /* DMQ_H */
