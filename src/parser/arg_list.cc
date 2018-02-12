//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// arg_list.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "arg_list.h"

#include <cstring>

void ArgList::dump()
{
    for ( int i = 0; i < argc; ++i )
        printf("argv[%d]='%s'\n", i, argv[i]);
}

// FIXIT-L this chokes on -n -4 because it thinks
// -4 is another arg instead of an option to -n
bool ArgList::get_arg(const char*& key, const char*& val)
{
    while ( ++idx < argc )
    {
        char* s = argv[idx];

        if ( arg )
        {
            key = arg;
            if ( s[0] != '-' )
                val = s;
            else
            {
                val = "";
                --idx;
            }
            arg = nullptr;
            return true;
        }
        if ( s[0] != '-' )
        {
            key = "";
            val = s;
            return true;
        }
        if ( s[1] != '-' )
        {
            s += 1;
            if ( strlen(s) > 1 )
            {
                buf.assign(s, 1);
                key = buf.c_str();
                val = s + 1;
                return true;
            }
            else if ( strlen(s) > 0 )
                arg = s;
            else
                arg = "-";
        }
        else
        {
            s += 2;
            char* eq = strchr(s, '=');

            if ( eq )
            {
                buf.assign(s, eq-s);
                key=buf.c_str();
                val = eq + 1;
                return true;
            }
            else
                arg = s;
        }
    }
    if ( arg )
    {
        key = arg;
        val = "";
        arg = nullptr;
        return true;
    }
    return false;
}

