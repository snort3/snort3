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
// arg_list.h author Russ Combs <rucombs@cisco.com>

#ifndef ARG_LIST_H
#define ARG_LIST_H

#include <string>

class ArgList
{
public:
    ArgList(int c, char* v[])
    { argc = c; argv = v; reset(); }

    void reset()
    { idx = 0; arg = nullptr; }

    bool get_arg(const char*& key, const char*& val);
    void dump();

private:
    char** argv;
    int argc, idx;
    const char* arg;
    std::string buf;
};

#endif

