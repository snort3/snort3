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

#ifndef SIDECHANNEL_H
#define SIDECHANNEL_H

#include "sidechannel_define.h"
#include "snort.h"

void SideChannelConfigure(SnortConfig *sc);
void SideChannelInit(void);
void SideChannelStartTXThread(void);
void SideChannelStopTXThread(void);
void SideChannelCleanUp(void);

void RegisterSideChannelModule(const char *keyword, SCMFunctionBundle *funcs);
void RegisterSideChannelModules(void);
int SideChannelRegisterRXHandler(uint16_t type, SCMProcessMsgFunc processMsgFunc, void *data);
int SideChannelRegisterTXHandler(uint16_t type, SCMProcessMsgFunc processMsgFunc, void *data);
void SideChannelUnregisterRXHandler(uint16_t type, SCMProcessMsgFunc processMsgFunc);
void SideChannelUnregisterTXHandler(uint16_t type, SCMProcessMsgFunc processMsgFunc);

/* RX Functions */
int SideChannelPreallocMessageRX(uint32_t length, SCMsgHdr **hdr_ptr, uint8_t **msg_ptr, void **msg_handle);
int SideChannelDiscardMessageRX(void *msg_handle);
int SideChannelEnqueueMessageRX(SCMsgHdr *hdr, const uint8_t *msg, uint32_t length, void *msg_handle, SCMQMsgFreeFunc msgFreeFunc);
int SideChannelEnqueueDataRX(SCMsgHdr *hdr, uint8_t *msg, uint32_t length, SCMQMsgFreeFunc msgFreeFunc);
uint32_t SideChannelDrainRX(unsigned max_msgs);

/* TX Functions */
int SideChannelPreallocMessageTX(uint32_t length, SCMsgHdr **hdr_ptr, uint8_t **msg_ptr, void **msg_handle);
int SideChannelDiscardMessageTX(void *msg_handle);
int SideChannelEnqueueMessageTX(SCMsgHdr *hdr, const uint8_t *msg, uint32_t length, void *msg_handle, SCMQMsgFreeFunc msgFreeFunc);
int SideChannelEnqueueDataTX(SCMsgHdr *hdr, uint8_t *msg, uint32_t length, SCMQMsgFreeFunc msgFreeFunc);

/* I/O Functions */
int SideChannelWriteMsgToFile(int fd, SCMsgHdr *hdr, const uint8_t *msg, uint32_t length);
int SideChannelReadMsgFromFile(int fd, SCMsgHdr *hdr, uint8_t **msg_ptr, uint32_t *length_ptr);

int SideChannelVerifyConfig(SnortConfig *sc);

int ConfigureSideChannelModule(const char *keyword, char *opts);
void SideChannelStats(const char *separator);
int SideChannelPostInit(void);

#endif
