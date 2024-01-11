//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

using namespace snort;

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
    sep = true;
    assert(level > 0);

    if ( --level == 0 and !level_array )
    {
        out << std::endl;
        sep = false;
    }
}

void JsonStream::open_array(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "[ ";
    sep = false;
    level_array++;
}

void JsonStream::close_array()
{
    out << " ]";
    sep = true;
    assert(level_array > 0);

    if ( --level_array == 0 and !level )
    {
        out << std::endl;
        sep = false;
    }
}

void JsonStream::put(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "null";
}

void JsonStream::put(const char* key, int64_t val)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << val;
}

void JsonStream::uput(const char* key, uint64_t val)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << val;
}

void JsonStream::put(const char* key, const char* val)
{
    if (val and val[0] == '\0')
        return;

    split();

    if ( key )
        out << std::quoted(key) << ": ";

    if (val)
        out << std::quoted(val);
    else
        out << "null";
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

void JsonStream::put(const char* key, double val, int precision)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out.precision(precision);
    out << std::fixed << val;
}

void JsonStream::put_true(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "true";
}

void JsonStream::put_false(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "false";
}

void JsonStream::split()
{
    if ( sep )
        out << ", ";
    else
        sep = true;
}

void JsonStream::put_eol()
{
    out << std::endl;
}
