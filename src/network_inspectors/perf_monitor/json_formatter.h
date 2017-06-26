//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// json_formatter.h author Carter Waxman <cwaxman@cisco.com>

#ifndef JSON_FORMATTER_H
#define JSON_FORMATTER_H

#include "perf_formatter.h"

class JSONFormatter : public PerfFormatter
{
public:
    using PerfFormatter::PerfFormatter;

    const char* get_extension() override
    { return ".json"; }

    bool allow_append() override
    { return false; }

    void init_output(FILE*) override;
    void write(FILE*, time_t) override;
    void finalize_output(FILE*) override;

private:
    bool first_write = true;
};

#endif

