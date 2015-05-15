//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

/*************************************************************************
 *
 * smtp_util.h
 *
 * Author: Andy Mullican
 * Author: Todd Wease
 *
 *************************************************************************/

#ifndef SMTP_UTIL_H
#define SMTP_UTIL_H

#include "smtp_config.h"
#include "protocols/packet.h"

void SMTP_GetEOL(const uint8_t*, const uint8_t*, const uint8_t**, const uint8_t**);
int SMTP_CopyToAltBuffer(Packet*, const uint8_t*, int);
int SMTP_CopyEmailHdrs(const uint8_t*, int, MAIL_LogState* log_state);
int SMTP_CopyEmailID(const uint8_t*, int, int, MAIL_LogState* log_state);
void SMTP_LogFuncs(SMTP_PROTO_CONF* config, Packet* p, MimeState* mime_ssn);
void SMTP_ResetAltBuffer(void);

#ifdef DEBUG_MSGS
const char* SMTP_PrintBuffer(Packet*);
#endif

#endif

