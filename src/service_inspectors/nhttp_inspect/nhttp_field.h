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
//  @brief      Field object
//

#ifndef NHTTP_FIELD_H
#define NHTTP_FIELD_H

#include <stdint.h>
#include <stdio.h>

// Individual pieces of the message found during parsing
// Length values <= 0 are StatusCode values and imply that the start pointer is meaningless.
// Never use the start pointer without verifying that length > 0.
class Field {
public:
    int32_t length = NHttpEnums::STAT_NOTCOMPUTE;
    const uint8_t* start = nullptr;

    Field(int32_t length_, const uint8_t* start_) : length(length_), start(start_) {};
    Field() = default;
    void print(FILE *output, const char* name, bool intVals = false) const;
};

#endif

























