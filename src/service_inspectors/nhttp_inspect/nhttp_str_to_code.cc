//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_str_to_code.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>

#include "main/snort_types.h"

#include "nhttp_enum.h"
#include "nhttp_str_to_code.h"

// Need to replace this simple algorithm for better performance FIXIT-P
SO_PUBLIC int32_t str_to_code(const uint8_t* text, const int32_t text_len, const StrCode table[])
{
    for (int32_t k=0; table[k].name != nullptr; k++)
    {
        if ((text_len == (int)strlen(table[k].name)) && (memcmp(text, table[k].name, text_len) ==
            0))
        {
            return table[k].code;
        }
    }
    return NHttpEnums::STAT_OTHER;
}

