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
// nhttp_field.cc author Tom Peters <thopeter@cisco.com>

#include <sys/types.h>
#include <stdio.h>

#include "nhttp_enum.h"
#include "nhttp_field.h"
#include "main/snort_types.h"

using namespace NHttpEnums;

const Field Field::FIELD_NULL { STAT_NOSOURCE };

void Field::print(FILE* output, const char* name, bool int_vals) const
{
    if ((length == STAT_NOTPRESENT) || (length == STAT_NOTCOMPUTE) || (length == STAT_NOSOURCE))
    {
        return;
    }
    const int out_count = fprintf(output, "%s, length = %d, ", name, length);
    if (length <= 0)
    {
        fprintf(output, "\n");
        return;
    }
    // Limit the amount of data printed
    const int32_t print_length = (length <= 1200) ? length : 1200;
    for (int k=0; k < print_length; k++)
    {
        if ((start[k] >= 0x20) && (start[k] <= 0x7E))
            fprintf(output, "%c", (char)start[k]);
        else if (start[k] == 0xD)
            fprintf(output, "~");
        else if (start[k] == 0xA)
            fprintf(output, "^");
        else
            fprintf(output, "*");
        if ((k%120 == (119 - out_count)) && (k+1 < print_length))
        {
            fprintf(output, "\n");
        }
    }

    if (int_vals && (print_length%8 == 0))
    {
        fprintf(output, "\nInteger values =");
        for (int j=0; j < print_length; j+=8)
        {
            // FIXIT-L rewrite to eliminate doubtful cast
            fprintf(output, " %" PRIu64, *((const uint64_t*)(start+j)));
        }
    }
    fprintf(output, "\n");
}

