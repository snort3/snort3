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
// directory.h author Russ Combs <rucombs@cisco.com>

#ifndef DIRECTORY_H
#define DIRECTORY_H

// simple directory traversal

#include <dirent.h>
#include <string>

class Directory
{
public:
    Directory(const char*, const char* filter = nullptr);
    ~Directory();

    int error_on_open();
    void rewind();
    const char* next();

private:
    DIR* dir;
    std::string root;
    std::string filter;
    std::string path;
    unsigned len;
    Directory* sub;
    int error;
};

#endif

