//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

/**
 * @file   util_str.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 27 10:34:37 2003
 *
 * @brief  string utility functions
 *
 * some string handling wrappers
 */

#ifndef UTIL_STR_H
#define UTIL_STR_H

int str2int(char* str, int* ret, int allow_negative);
int toggle_option(char* name, char* value, int* opt_value);

#endif /* UTIL_STR_H */

