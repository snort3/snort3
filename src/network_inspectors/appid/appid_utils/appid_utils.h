//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// appid_utils.h author Sourcefire Inc.

#ifndef SFUTIL_H
#define SFUTIL_H

#include <cstdio>
#include <cstdint>

#define MAX_TOKS    256

class AppIdUtils
{
public:
    static int tokenize(char* data, char* toklist[]);
    static int strip(char* data);
    static void init_netmasks(uint32_t netmasks[]);
    static int split(char* data, char** toklist, int max_toks, const char* separator);
    static void dump_hex(FILE*, const uint8_t* data, unsigned len);
};

#endif

