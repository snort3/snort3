//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// sfutil.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_utils.h"

#include <cctype>
#include <cstring>

int AppIdUtils::split(char* data, char** toklist, int max_toks, const char* separator)
{
    char** ap;
    int argcount = 0;

    memset(toklist, 0, max_toks * sizeof(*toklist));
    for (ap = (char**)toklist;
        ap < &toklist[max_toks] && (*ap = strsep(&data, separator)) != nullptr; )
    {
        if (**ap != '\0')
        {
            ap++;
            argcount++;
        }
    }

    return argcount;
}

void AppIdUtils::init_netmasks(uint32_t netmasks[])
{
    netmasks[0] = 0x0;
    netmasks[1] = 0x80000000;
    netmasks[2] = 0xC0000000;
    netmasks[3] = 0xE0000000;
    netmasks[4] = 0xF0000000;
    netmasks[5] = 0xF8000000;
    netmasks[6] = 0xFC000000;
    netmasks[7] = 0xFE000000;
    netmasks[8] = 0xFF000000;
    netmasks[9] = 0xFF800000;
    netmasks[10] = 0xFFC00000;
    netmasks[11] = 0xFFE00000;
    netmasks[12] = 0xFFF00000;
    netmasks[13] = 0xFFF80000;
    netmasks[14] = 0xFFFC0000;
    netmasks[15] = 0xFFFE0000;
    netmasks[16] = 0xFFFF0000;
    netmasks[17] = 0xFFFF8000;
    netmasks[18] = 0xFFFFC000;
    netmasks[19] = 0xFFFFE000;
    netmasks[20] = 0xFFFFF000;
    netmasks[21] = 0xFFFFF800;
    netmasks[22] = 0xFFFFFC00;
    netmasks[23] = 0xFFFFFE00;
    netmasks[24] = 0xFFFFFF00;
    netmasks[25] = 0xFFFFFF80;
    netmasks[26] = 0xFFFFFFC0;
    netmasks[27] = 0xFFFFFFE0;
    netmasks[28] = 0xFFFFFFF0;
    netmasks[29] = 0xFFFFFFF8;
    netmasks[30] = 0xFFFFFFFC;
    netmasks[31] = 0xFFFFFFFE;
    netmasks[32] = 0xFFFFFFFF;
}

int AppIdUtils::strip(char* data)
{
    int size;
    char* idx;

    idx = data;
    size = 0;

    while (*idx)
    {
        if ((*idx == '\n') || (*idx == '\r'))
        {
            *idx = 0;
            break;
        }
        if (*idx == '\t')
        {
            *idx = ' ';
        }
        size++;
        idx++;
    }

    return size;
}

int AppIdUtils::tokenize(char* data, char* toklist[])
{
    char** ap;
    int argcount = 0;
    int i = 0;
    char* tok;
    int drop_further = 0;

    for (ap = (char**)toklist; ap < &toklist[MAX_TOKS] && (*ap = strsep(&data, " ")) != nullptr; )
    {
        if (**ap != '\0')
        {
            ap++;
            argcount++;
        }
    }

    *ap = nullptr;

    /* scan for comments */
    while (i < argcount)
    {
        tok = toklist[i];

        if (tok[0] == '#' && !drop_further)
        {
            argcount = i;
            drop_further = 1;
        }

        if (drop_further)
        {
            toklist[i] = nullptr;
        }

        i++;
    }

    return argcount;
}

// FIXIT-L - refactor this to be a general snort utility...also look at LogBuffer() in u2spewfoo.cc
void AppIdUtils::dump_hex(FILE* fp, const uint8_t* data, unsigned len)
{
    char str[18];
    unsigned i;
    unsigned pos;
    char c;

    for (i=0, pos=0; i<len; i++, pos++)
    {
        if (pos == 17)
        {
            str[pos] = 0;
            fprintf(fp, "  %s\n", str);
            pos = 0;
        }
        else if (pos == 8)
        {
            str[pos] = ' ';
            pos++;
            fprintf(fp, "%s", " ");
        }
        c = (char)data[i];
        if (isprint(c) && !isspace(c))
            str[pos] = c;
        else
            str[pos] = '.';
        fprintf(fp, "%02X ", data[i]);
    }
    if (pos)
    {
        str[pos] = 0;
        for (; pos < 17; pos++)
        {
            if (pos == 8)
            {
                str[pos] = ' ';
                pos++;
                fprintf(fp, "%s", "    ");
            }
            else
            {
                fprintf(fp, "%s", "   ");
            }
        }
        fprintf(fp, "  %s\n", str);
    }
}

