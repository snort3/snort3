//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
 * @file   util_math.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 27 10:12:57 2003
 *
 * @brief  math related util functions
 *
 * Place simple math functions that are useful all over the place
 * here.
 */

#include "util_math.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/**
 * Calculate the percentage of something.
 *
 * If the total is <= 0, we return 0.
 *
 * @param amt amount to that you have
 * @param total amount there is
 *
 * @return a/b * 100
 */
double calc_percent(double amt, double total)
{
    if (total <= 0.0)
        return 0.0;

    return (amt/total) * 100.0;
}

