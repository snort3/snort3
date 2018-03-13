//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

// pp_telnet.h author Steven A. Sturges <ssturges@sourcefire.com>

#ifndef PP_TELNET_H
#define PP_TELNET_H

// declares the telnet checking functions

/* RFC 885 defines an End of Record telnet option */
#define RFC885
/* RFC 1184 defines Abort, Suspend, and End of File telnet options */
#define RFC1184

#include "ftpp_si.h"

/* define the telnet negotiation codes (TNC) that we're interested in */
#define TNC_IAC  0xFF
#define TNC_DONT 0xFE
#define TNC_DO   0xFD
#define TNC_WONT 0xFC
#define TNC_WILL 0xFB
#define TNC_SB   0xFA
#define TNC_GA   0xF9
#define TNC_EAL  0xF8
#define TNC_EAC  0xF7
#define TNC_AYT  0xF6
#define TNC_AO   0xF5
#define TNC_IP   0xF4
#define TNC_BRK  0xF3
#define TNC_DM   0xF2
#define TNC_NOP  0xF1
#define TNC_SE   0xF0
#ifdef RFC885
#define TNC_EOR  0xEF
#endif
#ifdef RFC1184
#define TNC_ABOR 0xEE
#define TNC_SUSP 0xED
#define TNC_EOF  0xEC
#endif

#define FTPP_APPLY_TNC_ERASE_CMDS 0
#define FTPP_IGNORE_TNC_ERASE_CMDS 1

/* list of function prototypes for this preprocessor */
extern int normalize_telnet(TELNET_SESSION*, snort::Packet*, int iMode, char ignoreEraseCmd);

void reset_telnet_buffer(snort::Packet*);
const uint8_t* get_telnet_buffer(snort::Packet*, unsigned&);

#endif

