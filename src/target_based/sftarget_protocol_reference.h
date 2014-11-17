/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2006-2013 Sourcefire, Inc.
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

/*
 * Author: Steven Sturges
 * sftarget_protocol_reference.h
 */

#ifndef SFTARGET_PROTOCOL_REFERENCE_H
#define SFTARGET_PROTOCOL_REFERENCE_H

#include "snort_types.h"

#define MAX_PROTOCOL_ORDINAL 8192

extern int16_t protocolReferenceTCP;
extern int16_t protocolReferenceUDP;
extern int16_t protocolReferenceICMP;

void InitializeProtocolReferenceTable(void);
void FreeProtoocolReferenceTable(void);

const char* get_protocol_name(uint16_t id);
int16_t AddProtocolReference(const char *protocol);
SO_PUBLIC int16_t FindProtocolReference(const char *protocol);

int16_t GetProtocolReference(struct Packet*);

#endif

