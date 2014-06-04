/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief     Converts token strings to enum codes
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_str_to_code.h"

// Need to replace this simple algorithm for better performance
int32_t strToCode(const uint8_t *text, int32_t textLen, const StrCode table[]) {
    if (textLen <= 0) return NHttpEnums::STAT_PROBLEMATIC;
    for (int32_t k=0; table[k].name != nullptr; k++) {
        if ((textLen == (int) strlen(table[k].name)) && (memcmp(text, table[k].name, textLen) == 0)) {
            return table[k].code;
        }
    }
    return NHttpEnums::STAT_OTHER;
}

