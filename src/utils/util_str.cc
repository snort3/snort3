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

/*
 * @file   util_str.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 27 10:41:59 2003
 *
 * @brief  utility string functions
 */

#include "util_str.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <strings.h>

/**
 * Convert a string to an int and check for problems
 *
 * @param str string to parse as an int
 * @param ret return value for the int
 * @param allow_negative allow negative values
 *
 * @return 0 on sucess, else failure
 */
int str2int(char* str, int* ret, int allow_negative)
{
    char* endptr;
    long int value;

    if (ret && str && *str != '\0')
    {
        value = strtol(str, &endptr, 10);

        if (endptr == str)
        {
            /* parsing has failed */
            return -1;
        }

        if (!allow_negative)
        {
            if (value < 0)
            {
                return -1;
            }
        }

        *ret = value;

        return 0;
    }

    return -1;
}

/**
 * Set opt_value to 1 if the value is on, 0 if it's off
 *
 * @param name option name to configure (not used but useful for debugging)
 * @param value value to configure (should be either on or off )
 * @param opt_value ptr to integer to configure
 *
 * @returns 0 on success , else failure
 */
int toggle_option(char* name, char* value, int* opt_value)
{
    int opt_on, opt_off;

    if (!name || !value || !opt_value || (*value == '\0') || (*name == '\0') )
        return -1;

    opt_on  = strcasecmp(value,"on");
    opt_off = strcasecmp(value,"off");

    if (opt_off && opt_on)
    {
        /*
     * the string is neither "on" or "off"
     *
     * we don't know what the hell we're looking at. return error.
     */
        return -2;
    }

    if (opt_on == 0)
        *opt_value = 1;
    else
        *opt_value = 0;

    return 0;
}

#ifdef TEST_UTIL_STR
int main(void)
{
    int value;

    printf("you should see 4 pass messages\n");

    if (str2int("-1",&value,0) != 0)
        printf("test 1 passed and failed to parse\n");

    if (str2int("-1",&value,1) == 0 && value == -1)
        printf("test 2 passed: %d\n", value);

    if (str2int("0",&value,1) == 0 && value == 0 )
        printf("test 3 passed: %d\n", value);

    if (str2int("124",&value,1) == 0 && value == 124 )
        printf("test 4 passed: %d\n", value);
}

#endif /* TEST_UTIL_STR */

