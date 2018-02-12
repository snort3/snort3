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
// directory.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "directory.h"

#include <fnmatch.h>
#include <sys/stat.h>

#include <cerrno>
#include <climits>
#include <cstring>

Directory::Directory(const char* s, const char* f)
{
    dir = opendir(s);
    root = s;
    len = strlen(s);
    path = root;
    sub = nullptr;
    filter = f ? f : "";
    error = dir ? 0 : errno;
}

Directory::~Directory()
{
    if ( dir )
        closedir(dir);

    if ( sub )
        delete sub;
}

int Directory::error_on_open()
{
    return error;
}

void Directory::rewind()
{
    if ( dir )
        rewinddir(dir);

    if ( sub )
        delete sub;
}

const char* Directory::next()
{
    if ( sub )
    {
        const char* s = sub->next();

        if ( s )
            return s;

        delete sub;
        sub = nullptr;
    }

    struct dirent de, * result;

    while ( dir && !readdir_r(dir, &de, &result) )
    {
        if ( !result )
            break;

        struct stat sb;

        if ( !strncmp(de.d_name, ".", 1) )
            continue;

        path.erase(len);
        path += "/";
        path += de.d_name;

        if ( path.size() > PATH_MAX - 1 || stat(path.c_str(), &sb) )
            continue;

        if ( S_ISDIR(sb.st_mode) )
        {
            sub = new Directory(path.c_str(), filter.c_str());
            return next();
        }
        else if ( !S_ISREG(sb.st_mode) )
        {
            continue;
        }
        else if ( !filter.empty() && fnmatch(filter.c_str(), de.d_name, 0) )
        {
            continue;
        }
        return path.c_str();
    }
    return nullptr;
}

