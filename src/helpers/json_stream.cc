//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// json_stream.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "json_stream.h"

#include <cassert>
#include <iomanip>

void JsonStream::open(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "{ ";
    sep = false;
    ++level;
}

void JsonStream::close()
{
    out << " }";
    assert(level > 0);

    if ( --level == 0 )
    {
        out << std::endl;
        sep = false;
    }
}

void JsonStream::open_array(const char* key)
{
    split();
    out << std::quoted(key) << ": [ ";
    sep = false;
}

void JsonStream::close_array()
{
    out << " ]";
    sep = true;
}

void JsonStream::put(const char* key, long val)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << val;
}

void JsonStream::put(const char* key, const std::string& val)
{
    if ( val.empty() )
        return;

    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << std::quoted(val);
}

void JsonStream::split()
{
    if ( sep )
        out << ", ";
    else
        sep = true;
}

