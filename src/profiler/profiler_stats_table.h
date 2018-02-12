//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// profiler_stats_table.h author Joel Cornett <jocornet@cisco.com>

#ifndef PROFILER_STATS_TABLE_H
#define PROFILER_STATS_TABLE_H

#include <iostream>
#include <vector>

class StatsTable
{
public:
    struct Field
    {
        const char* name;
        int width;
        char fill;
        int precision;
        std::ios_base::fmtflags flags;
    };

    StatsTable(const Field*, std::ostream&);
    ~StatsTable();

    struct Header
    { char c; };

    struct Sep
    { char c; };

    struct Row {};

    static const Header HEADER;
    static const Sep SEP;
    static const Row ROW;

    void header(char);
    void sep(char);
    void row();

    template<typename T>
    StatsTable& operator<<(T v)
    {
        if ( cur )
        {
            if ( !cur->name )
                finish();

            else
                format(*cur++);
        }

        os << v;

        return *this;
    }

    StatsTable& operator<<(Header);
    StatsTable& operator<<(Sep);
    StatsTable& operator<<(Row);

    void finish();

    std::string next()
    {
        if ( !cur || !cur->name )
            return "";

        return cur->name;
    }

private:
    void format(const Field&);

    const Field* fields;
    std::ostream& os;

    const Field* cur;
};

#endif
