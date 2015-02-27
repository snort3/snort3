//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// directory.cc author Russ Combs <rucombs@cisco.com>

#include "directory.h"

#include <dirent.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <iostream>
#include <string>
using namespace std;

Directory::Directory(const char* s, const char* f)
{
    dir = opendir(s);
    path = s;
    len = strlen(s);
    sub = nullptr;
    filter = f ? f : "";
}

Directory::~Directory()
{
    if ( dir )
        closedir(dir);

    if ( sub )
        delete sub;
}

void Directory::rewind()
{
    if ( dir )
        rewinddir(dir);

    if ( sub )
        delete sub;
}

static bool is_sub(const char* path)
{
    struct stat s;
    unsigned n = strlen(path);

    if ( !n || path[n-1] == '.' )
        return false;

    if ( stat(path, &s) )
        return false;

    return (s.st_mode & S_IFDIR) != 0;
}

const char* Directory::next(const char* ext)
{
    if ( sub )
    {
        const char* s = sub->next(ext);

        if ( s )
            return s;

        delete sub;
        sub = nullptr;
    }
    struct dirent de, * dummy;

    while ( dir && !readdir_r(dir, &de, &dummy) )
    {
        if ( !dummy )
            break;

        path.erase(len);
        path += "/";
        path += de.d_name;

        if ( is_sub(path.c_str()) )
        {
            sub = new Directory(path.c_str());
            return next(ext);
        }
        else if ( ext )
        {
            if ( filter.size() && fnmatch(path.c_str(), filter.c_str(), 0) )
                continue;

            const char* p = strrchr(de.d_name, '.');

            if ( !p || strcmp(p, ext) )
                continue;
        }
        return path.c_str();
    }
    return nullptr;
}

