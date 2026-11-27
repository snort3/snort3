//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

#ifndef NUM_FORMAT_H
#define NUM_FORMAT_H

// thousands grouping for human readable text output
// configured with output.thousands_separator; '\0' means no grouping

#include <cstdint>
#include <locale>
#include <string>

#include "main/snort_types.h"

namespace snort
{
SO_PUBLIC void set_thousands_separator(char);
SO_PUBLIC char get_thousands_separator();

// '.' normally, ',' when the thousands separator is '.'
SO_PUBLIC char get_decimal_point();

SO_PUBLIC std::string format_count(uint64_t);
SO_PUBLIC std::string format_signed(int64_t);

// swap '.' for the configured decimal point in place
SO_PUBLIC void localize_decimal(char*);

// classic locale with the configured grouping, for iostreams
SO_PUBLIC std::locale count_locale();
}

#endif
