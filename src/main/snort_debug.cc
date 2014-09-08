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

#include "snort_debug.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#ifndef __USE_ISOC95
# define __USE_ISOC95
# include <wchar.h>
# undef __USE_ISOC95
#else
# include <wchar.h>
#endif
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>

#include "snort_types.h"
#include "snort.h"

#ifdef DEBUG_MSGS
const char *DebugMessageFile = NULL;  // FIXIT-M use access methods
int DebugMessageLine = 0;  // FIXIT-M use access methods

int DebugThis(uint64_t level)
{
    if (!(level & GetDebugLevel()))
        return 0;

    return 1;
}

uint64_t GetDebugLevel(void)
{
    static int debug_init = 0;
    static uint64_t debug_level = 0;

    const char* key;

    if ( debug_init )
        return debug_level;

    key = getenv(DEBUG_PP_VAR);

    if ( key )
        debug_level = strtoul(key, NULL, 0);

    debug_level <<= 32;

    key = getenv(DEBUG_VARIABLE);

    if ( key )
        debug_level |= strtoul(key, NULL, 0);

    debug_init = 1;

    return debug_level;
}

void DebugMessageFunc(uint64_t level, const char *fmt, ...)
{
    va_list ap;

    if (!(level & GetDebugLevel()))
        return;

    va_start(ap, fmt);

    if ((snort_conf != NULL) && ScDaemonMode())
    {
        char buf[STD_BUF];
        int buf_len = sizeof(buf);
        char *buf_ptr = buf;

        buf[buf_len - 1] = '\0';

        /* filename and line number information */
        if (DebugMessageFile != NULL)
        {
            snprintf(buf, buf_len - 1, "%s:%d: ",
                    DebugMessageFile, DebugMessageLine);
            buf_ptr += strlen(buf);
            buf_len -= strlen(buf);
        }

        vsnprintf(buf_ptr, buf_len - 1, fmt, ap);
        syslog(LOG_DAEMON | LOG_DEBUG, "%s", buf);
    }
    else
    {
        if (DebugMessageFile != NULL)
            printf("%s:%d: ", DebugMessageFile, DebugMessageLine);
        vprintf(fmt, ap);
    }

    va_end(ap);
}

#ifdef SF_WCHAR
void DebugWideMessageFunc(uint64_t level, const wchar_t *fmt, ...)
{
    va_list ap;
    wchar_t buf[STD_BUF+1];


    if (!(level & GetDebugLevel()))
    {
        return;
    }
    buf[STD_BUF]= (wchar_t)0;

    /* filename and line number information */
    if (DebugMessageFile != NULL)
        printf("%s:%d: ", DebugMessageFile, DebugMessageLine);

    va_start(ap, fmt);

    if (ScDaemonMode())
    {
#ifdef HAVE_VSWPRINTF
        vswprintf(buf, STD_BUF, fmt, ap);
#endif
        //syslog(LOG_DAEMON | LOG_DEBUG, "%s", buf);
    }
    else
    {
#ifdef HAVE_WPRINTF
        vwprintf(fmt, ap);
#endif
    }

    va_end(ap);
}
#endif
#else /* DEBUG_MSGS */
void DebugMessageFunc(uint64_t /*level*/, const char* /*fmt*/, ...)
{
}
#ifdef SF_WCHAR
void DebugWideMessageFunc(uint64_t /*level*/, const wchar_t* /*fmt*/, ...)
{
}
#endif
#endif /* DEBUG_MSGS */
