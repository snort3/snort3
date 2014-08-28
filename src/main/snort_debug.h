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


#ifndef SNORT_DEBUG_H
#define SNORT_DEBUG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <ctype.h>

#ifdef SF_WCHAR
/* ISOC99 is defined to get required prototypes */
#ifndef __USE_ISOC99
#define __USE_ISOC99
#endif
#include <wchar.h>
#endif

#include "snort_types.h"

// this env var uses the lower 32 bits of the flags:
#define DEBUG_VARIABLE "SNORT_DEBUG"

#define DEBUG_INIT            0x0000000000000001LL
#define DEBUG_PARSER          0x0000000000000002LL
#define DEBUG_MSTRING         0x0000000000000004LL
#define DEBUG_PORTLISTS       0x0000000000000008LL
#define DEBUG_ATTRIBUTE       0x0000000000000010LL
#define DEBUG_PLUGIN          0x0000000000000020LL
#define DEBUG_PLUGBASE        0x0000000000000040LL
#define DEBUG_DECODE          0x0000000000000080LL
#define DEBUG_DATALINK        0x0000000000000100LL
#define DEBUG_CONFIGRULES     0x0000000000000200LL
#define DEBUG_RULES           0x0000000000000400LL
#define DEBUG_DETECT          0x0000000000000800LL
#define DEBUG_PATTERN_MATCH   0x0000000000001000LL
#define DEBUG_FLOW            0x0000000000002000LL
#define DEBUG_LOG             0x0000000000004000LL
#define DEBUG_FLOWBITS        0x0000000000008000LL
#define DEBUG_FILE            0x0000000000010000LL
#define DEBUG_CONTROL         0x0000000000020000LL
#define DEBUG_EXP             0x0000000080000000LL

// this env var uses the upper 32 bits of the flags:
#define DEBUG_PP_VAR   "SNORT_PP_DEBUG"

#define DEBUG_FRAG            0x0000000100000000LL
#define DEBUG_STREAM          0x0000000200000000LL
#define DEBUG_STREAM_STATE    0x0000000400000000LL
#define DEBUG_STREAM_PAF      0x0000000800000000LL
#define DEBUG_HTTP_DECODE     0x0000001000000000LL
#define DEBUG_HTTPINSPECT     0x0000002000000000LL
#define DEBUG_ASN1            0x0000004000000000LL
#define DEBUG_DNS             0x0000008000000000LL
#define DEBUG_FTPTELNET       0x0000010000000000LL
#define DEBUG_GTP             0x0000020000000000LL
#define DEBUG_IMAP            0x0000040000000000LL
#define DEBUG_POP             0x0000080000000000LL
#define DEBUG_RPC             0x0000100000000000LL
#define DEBUG_SIP             0x0000200000000000LL
#define DEBUG_SKYPE           0x0000400000000000LL
#define DEBUG_SSL             0x0000800000000000LL
#define DEBUG_SMTP            0x0001000000000000LL
#define DEBUG_PP_EXP          0x8000000000000000LL

SO_PUBLIC void DebugMessageFunc(uint64_t dbg, const char *fmt, ...);
#ifdef SF_WCHAR
void DebugWideMessageFunc(uint64_t dbg, const wchar_t *fmt, ...);
#endif

#ifdef DEBUG_MSGS

SO_PUBLIC extern const char *DebugMessageFile;
SO_PUBLIC extern int DebugMessageLine;

#define DebugMessage DebugMessageFile = __FILE__; DebugMessageLine = __LINE__; DebugMessageFunc
#define DebugWideMessage DebugMessageFile = __FILE__; DebugMessageLine = __LINE__; DebugWideMessageFunc

uint64_t GetDebugLevel (void);
int DebugThis(uint64_t level);
#endif /* DEBUG_MSGS */


#ifdef DEBUG_MSGS
#define DEBUG_WRAP(code) code
SO_PUBLIC void DebugMessageFunc(uint64_t dbg, const char *fmt, ...);
#ifdef SF_WCHAR
SO_PUBLIC void DebugWideMessageFunc(uint64_t dbg, const wchar_t *fmt, ...);
#endif
#else /* DEBUG_MSGS */
#define DEBUG_WRAP(code)
/* I would use DebugMessage(dbt,fmt...) but that only works with GCC */

#endif /* DEBUG_MSGS */

#endif /* SNORT_DEBUG_H */

