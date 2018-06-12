//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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

/**
 * @file   log/text_log.c
 * @author Russ Combs <rcombs@sourcefire.com>
 * @date
 *
 * @brief  implements buffered text stream for logging
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "text_log.h"

#include <sys/stat.h>

#include <cstdarg>

#include "utils/util.h"

#include "log.h"

using namespace snort;

/* a reasonable minimum */
#define MIN_BUF  (4* K_BYTES)
#define STDLOG_FILENO 3

struct TextLog
{
/* private:
   file attributes: */
    FILE* file;
    char* name;
    size_t size;
    size_t maxFile;
    time_t last;

/* buffer attributes: */
    unsigned int pos;
    unsigned int maxBuf;
    char buf[1];
};

/*-------------------------------------------------------------------
 * TextLog_Open/Close: open/close associated log file
 *-------------------------------------------------------------------
 */
static FILE* TextLog_Open(const char* name)
{
    if ( name && !strcasecmp(name, "stdout") )
    {
#ifdef USE_STDLOG
        FILE* stdlog = fdopen(STDLOG_FILENO, "w");
        return stdlog ? stdlog : stdout;
#else
        return stdout;
#endif
    }

    return OpenAlertFile(name);
}

static void TextLog_Close(FILE* file)
{
    if ( !file )
        return;
    if ( file != stdout )
        fclose(file);
}

static size_t TextLog_Size(FILE* file)
{
    struct stat sbuf;
    int fd = fileno(file);
    int err = fstat(fd, &sbuf);
    return err ? 0 : sbuf.st_size;
}

int TextLog_Tell(TextLog* const txt)
{
    return txt->pos;
}

namespace snort
{
int TextLog_Avail(TextLog* const txt)
{
    return txt->maxBuf - txt->pos - 1;
}

void TextLog_Reset(TextLog* const txt)
{
    txt->pos = 0;
    txt->buf[txt->pos] = '\0';
}

/*-------------------------------------------------------------------
 * TextLog_Init: constructor
 *-------------------------------------------------------------------
 */
TextLog* TextLog_Init(
    const char* name, unsigned int maxBuf, size_t maxFile)
{
    TextLog* txt;

    if ( maxBuf < MIN_BUF )
        maxBuf = MIN_BUF;

    txt = (TextLog*)snort_alloc(sizeof(TextLog)+maxBuf);

    txt->name = name ? snort_strdup(name) : nullptr;
    txt->file = TextLog_Open(txt->name);
    txt->size = TextLog_Size(txt->file);
    txt->last = time(nullptr);
    txt->maxFile = maxFile;

    txt->maxBuf = maxBuf;
    TextLog_Reset(txt);

    return txt;
}

/*-------------------------------------------------------------------
 * TextLog_Term: destructor
 *-------------------------------------------------------------------
 */
void TextLog_Term(TextLog* const txt)
{
    if ( !txt )
        return;

    TextLog_Flush(txt);
    TextLog_Close(txt->file);

    if ( txt->name )
        snort_free(txt->name);
    snort_free(txt);
}

/*-------------------------------------------------------------------
 * TextLog_Flush: start writing to new file
 * but don't roll over stdout or any sooner
 * than resolution of filename discriminator
 *-------------------------------------------------------------------
 */
static void TextLog_Roll(TextLog* const txt)
{
    if ( txt->file == stdout )
        return;
    if ( txt->last >= time(nullptr) )
        return;

    TextLog_Close(txt->file);
    RollAlertFile(txt->name);
    txt->file = TextLog_Open(txt->name);

    txt->last = time(nullptr);
    txt->size = 0;
}

/*-------------------------------------------------------------------
 * TextLog_Flush: write buffered stream to file
 *-------------------------------------------------------------------
 */
bool TextLog_Flush(TextLog* const txt)
{
    int ok;

    if ( !txt->pos )
        return false;

    if ( txt->maxFile and txt->size + txt->pos > txt->maxFile )
        TextLog_Roll(txt);

    ok = fwrite(txt->buf, txt->pos, 1, txt->file);

    if ( ok == 1 )
    {
        txt->size += txt->pos;
        TextLog_Reset(txt);
        return true;
    }
    return false;
}

/*-------------------------------------------------------------------
 * TextLog_Putc: append char to buffer
 *-------------------------------------------------------------------
 */
bool TextLog_Putc(TextLog* const txt, char c)
{
    if ( TextLog_Avail(txt) < 1 )
    {
        TextLog_Flush(txt);
    }
    txt->buf[txt->pos++] = c;
    txt->buf[txt->pos] = '\0';

    return true;
}

/*-------------------------------------------------------------------
 * TextLog_Write: append string to buffer
 *-------------------------------------------------------------------
 */
bool TextLog_Write(TextLog* const txt, const char* str, int len)
{
    int avail = TextLog_Avail(txt);

    if ( len >= avail )
    {
        TextLog_Flush(txt);
        avail = TextLog_Avail(txt);
    }
    int n = snprintf(txt->buf+txt->pos, avail, "%.*s", len, str);

    if ( n != len )
        return false;

    txt->pos += len;
    return true;
}

/*-------------------------------------------------------------------
 * TextLog_Printf: append formatted string to buffer
 *-------------------------------------------------------------------
 */
bool TextLog_Print(TextLog* const txt, const char* fmt, ...)
{
    int avail = TextLog_Avail(txt);
    int len;
    va_list ap;

    va_start(ap, fmt);
    len = vsnprintf(txt->buf+txt->pos, avail, fmt, ap);
    va_end(ap);

    if ( len >= avail )
    {
        TextLog_Flush(txt);
        avail = TextLog_Avail(txt);

        va_start(ap, fmt);
        len = vsnprintf(txt->buf+txt->pos, avail, fmt, ap);
        va_end(ap);
    }
    if ( len >= avail )
    {
        txt->pos = txt->maxBuf - 1;
        txt->buf[txt->pos] = '\0';
        return false;
    }
    else if ( len < 0 )
    {
        return false;
    }
    txt->pos += len;
    return true;
}

/*-------------------------------------------------------------------
 * TextLog_Quote: write string escaping quotes
 * TBD could be smarter by counting required escapes instead of
 * checking for 3
 *-------------------------------------------------------------------
 */
bool TextLog_Quote(TextLog* const txt, const char* qs)
{
    int pos = txt->pos;

    if ( TextLog_Avail(txt) < 3 )
    {
        TextLog_Flush(txt);
    }
    txt->buf[pos++] = '"';

    while ( *qs && (txt->maxBuf - pos > 2) )
    {
        if ( *qs == '"' || *qs == '\\' )
        {
            txt->buf[pos++] = '\\';
        }
        txt->buf[pos++] = *qs++;
    }
    if ( *qs )
        return false;

    txt->buf[pos++] = '"';
    txt->pos = pos;

    return true;
}
} // namespace snort
