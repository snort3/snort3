//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#include "snort_debug.h"

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>

#include "snort_types.h"
#include "snort_config.h"

bool Debug::init = false;
uint64_t Debug::mask = 0;

bool Debug::enabled(uint64_t flag)
{
    if ( !init )
    {
        const char* b = getenv(DEBUG_BUILTIN);
        const char* p = getenv(DEBUG_PLUGIN);

        mask = p ? (strtoul(p, nullptr, 0) << 32) : 0;
        mask |= (b ? strtoul(b, NULL, 0) : 0);

        init = true;
    }

    return (mask & flag) != 0;
}

void Debug::print(
    const char* file, int line, uint64_t dbg, const char* fmt, ...)
{
    if ( !enabled(dbg) )
        return;

    va_list ap;
    va_start(ap, fmt);

    if ( snort_conf and SnortConfig::log_syslog() )
    {
        char buf[STD_BUF];
        int buf_len = sizeof(buf);
        char* buf_ptr = buf;

        buf[buf_len - 1] = '\0';

        /* filename and line number information */
        if ( file )
        {
            snprintf(buf, buf_len - 1, "%s:%d: ", file, line);
            buf_ptr += strlen(buf);
            buf_len -= strlen(buf);
        }

        vsnprintf(buf_ptr, buf_len - 1, fmt, ap);
        syslog(LOG_DAEMON | LOG_DEBUG, "%s", buf);
    }
    else
    {
        if ( file )
            printf("%s:%d: ", file, line);
        vprintf(fmt, ap);
    }

    va_end(ap);
}
