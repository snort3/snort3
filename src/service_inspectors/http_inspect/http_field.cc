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
// http_field.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_field.h"

#include "http_test_manager.h"

using namespace HttpEnums;

const Field Field::FIELD_NULL { STAT_NO_SOURCE };

void Field::set(int32_t length, const uint8_t* start, bool own_the_buffer_)
{
    assert(len == STAT_NOT_COMPUTE);
    assert(strt == nullptr);
    assert(start != nullptr);
    assert(length >= 0);
    assert(length <= MAX_OCTETS);
    strt = start;
    len = length;
    own_the_buffer = own_the_buffer_;
}

void Field::set(StatusCode stat_code)
{
    assert(len == STAT_NOT_COMPUTE);
    assert(strt == nullptr);
    assert(stat_code <= 0);
    len = stat_code;
}

void Field::set(const Field& f)
{
    assert(len == STAT_NOT_COMPUTE);
    assert(strt == nullptr);
    strt = f.strt;
    len = f.len;
    // Both Fields cannot be responsible for deleting the buffer so do not copy own_the_buffer
}

#ifdef REG_TEST
void Field::print(FILE* output, const char* name) const
{
    if ((len == STAT_NOT_PRESENT) || (len == STAT_NOT_COMPUTE) || (len == STAT_NO_SOURCE))
    {
        return;
    }
    const int out_count = fprintf(output, "%s, length = %d, ", name, len);
    if (len <= 0)
    {
        fprintf(output, "\n");
        return;
    }
    // Limit the amount of data printed
    const int32_t print_length = (len <= HttpTestManager::get_print_amount()) ? len :
        HttpTestManager::get_print_amount();
    for (int32_t k=0; k < print_length; k++)
    {
        if ((strt[k] >= 0x20) && (strt[k] <= 0x7E))
            fprintf(output, "%c", (char)strt[k]);
        else if (strt[k] == 0xD)
            fprintf(output, "~");
        else if (strt[k] == 0xA)
            fprintf(output, "^");
        else if (HttpTestManager::get_print_hex())
            fprintf(output, "[%.2x]", (uint8_t)strt[k]);
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

