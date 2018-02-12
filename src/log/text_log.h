//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

// text_log.h Russ Combs <rcombs@sourcefire.com>

#ifndef TEXT_LOG_H
#define TEXT_LOG_H

/*
 * Declares a TextLog_*() api for buffered logging.  This allows
 * relatively painless transition from fprintf(), fwrite(), etc.
 * to a buffer that is formatted in memory and written with one
 * fwrite().
 *
 * Additionally, the file is capped at a maximum size.  Beyond
 * that, the file is closed, renamed, and reopened.  The current
 * file always has the same name.  Old files are renamed to that
 * name plus a timestamp.
 */

#include <cstring>

#include "main/snort_types.h"

#define K_BYTES (1024)
#define M_BYTES (K_BYTES*K_BYTES)
#define G_BYTES (K_BYTES*M_BYTES)

// FIXIT-L need a LogMessage based subclass of TextLog
// or some such to get stdout or syslog
struct TextLog;

SO_PUBLIC TextLog* TextLog_Init(
    const char* name, unsigned int maxBuf = 0, size_t maxFile = 0);
SO_PUBLIC void TextLog_Term(TextLog*);

SO_PUBLIC bool TextLog_Putc(TextLog* const, char);
SO_PUBLIC bool TextLog_Quote(TextLog* const, const char*);
SO_PUBLIC bool TextLog_Write(TextLog* const, const char*, int len);
SO_PUBLIC bool TextLog_Print(TextLog* const, const char* format, ...);

SO_PUBLIC bool TextLog_Flush(TextLog* const);
SO_PUBLIC int TextLog_Tell(TextLog* const);
SO_PUBLIC int TextLog_Avail(TextLog* const);
SO_PUBLIC void TextLog_Reset(TextLog* const);

/*-------------------------------------------------------------------
  * helper functions
  *-------------------------------------------------------------------
  */
inline bool TextLog_NewLine(TextLog* const txt)
{
    return TextLog_Putc(txt, '\n');
}

inline bool TextLog_Puts(TextLog* const txt, const char* str)
{
    return TextLog_Write(txt, str, strlen(str));
}

#endif

