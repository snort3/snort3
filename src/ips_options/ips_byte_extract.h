/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2010-2013 Sourcefire, Inc.
** Author: Ryan Jordan <ryan.jordan@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef IPS_BYTE_EXTRACT_H
#define IPS_BYTE_EXTRACT_H

#include <stdint.h>

#define NUM_BYTE_EXTRACT_VARS 2
#define BYTE_EXTRACT_NO_VAR -1
#define BYTE_EXTRACT_INVALID_ERR_STR "Rule option uses an undefined byte_extract variable name."

int8_t GetVarByName(char *name);

int GetByteExtractValue(uint32_t *dst, int8_t var_number);
int SetByteExtractValue(uint32_t value, int8_t var_number);

#endif

