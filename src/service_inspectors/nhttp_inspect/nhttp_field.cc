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
// nhttp_field.cc author Tom Peters <thopeter@cisco.com>

#include <sys/types.h>
#include <stdio.h>

#include "main/snort_types.h"

#include "nhttp_enum.h"
#include "nhttp_test_manager.h"
#include "nhttp_field.h"

using namespace NHttpEnums;

const Field Field::FIELD_NULL { STAT_NO_SOURCE };
void Field::set(int32_t length_, const uint8_t* start_)
{
    assert(length == STAT_NOT_COMPUTE);
    assert(start == nullptr);
    assert(start_ != nullptr);
    assert(length_ >= 0);
    assert(length_ <= MAX_OCTETS);
    start = start_;
    length = length_;
}

void Field::set(StatusCode stat_code)
{
    assert(length == STAT_NOT_COMPUTE);
    assert(start == nullptr);
    assert(stat_code <= 0);
    start = nullptr;
    length = stat_code;
}

void Field::set(const Field& f)
{
    assert(length == STAT_NOT_COMPUTE);
    assert(start == nullptr);
    start = f.start;
    length = f.length;
}

#ifdef REG_TEST
void Field::print(FILE* output, const char* name) const
{
    if ((length == STAT_NOT_PRESENT) || (length == STAT_NOT_COMPUTE) || (length == STAT_NO_SOURCE))
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
    const int32_t print_length = (length <= NHttpTestManager::get_print_amount()) ? length :
        NHttpTestManager::get_print_amount();
    for (int32_t k=0; k < print_length; k++)
    {
        if ((start[k] >= 0x20) && (start[k] <= 0x7E))
            fprintf(output, "%c", (char)start[k]);
        else if (start[k] == 0xD)
            fprintf(output, "~");
        else if (start[k] == 0xA)
            fprintf(output, "^");
        else if (NHttpTestManager::get_print_hex())
            fprintf(output, "[%.2x]", (uint8_t)start[k]);
        else
            fprintf(output, "*");
        if ((k%120 == (119 - out_count)) && (k+1 < print_length))
        {
            fprintf(output, "\n");
        }
    }
    fprintf(output, "\n");
}
#endif

