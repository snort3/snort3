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
#include "hi_cmd_lookup.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utils/kmap.h"

/*
 * Function: http_cmd_lookup_init(CMD_LOOKUP **CmdLookup)
 *
 * Purpose: Initialize the cmd_lookup structure.
 *
 *          We need to initialize the cmd_lookup structure for
 *          the HTTP command configuration.  Don't want a NULL pointer
 *          flying around, when we have to look for HTTP commands.
 *
 * Arguments: CmdLookup         => pointer to the pointer of the cmd
 *                                 lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int http_cmd_lookup_init(CMD_LOOKUP** CmdLookup)
{
    KMAP* km = KMapNew((KMapUserFreeFunc)HttpInspectCleanupHttpMethodsConf);
    *CmdLookup = km;
    if (*CmdLookup == NULL)
    {
        return -1;
    }

    km->nocase = 1;

    return 0;
}

/*
 * Function: http_cmd_lookup_cleanup(CMD_LOOKUP **CmdLookup)
 *
 * Purpose: Free the cmd_lookup structure.
 *          We need to free the cmd_lookup structure.
 *
 * Arguments: CmdLookup     => pointer to the pointer of the cmd
 *                             lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int http_cmd_lookup_cleanup(CMD_LOOKUP** CmdLookup)
{
    KMAP* km;

    if (CmdLookup == NULL)
        return -1;

    km = *CmdLookup;

    if (km)
    {
        KMapDelete(km);
        *CmdLookup = NULL;
    }

    return 0;
}

// Add a cmd configuration to the list.  We add these keys like you would
// normally think to add them, because on low endian machines the least
// significant byte is compared first.  This is what we want to compare IPs
// backward, doesn't work on high endian machines, but oh well.  Our
// platform is Intel.  FIXIT-L say what?  endian madness

int http_cmd_lookup_add(CMD_LOOKUP* CmdLookup, char* cmd, int len,
    HTTP_CMD_CONF* HTTPCmd)
{
    int iRet;

    if (!CmdLookup || !HTTPCmd)
    {
        return -1;
    }

    iRet = KMapAdd(CmdLookup, (void*)cmd, len, (void*)HTTPCmd);
    if (iRet)
    {
        /*
         * This means the key has already been added.
         */
        if (iRet == 1)
        {
            return -1;
        }
        else
        {
            return -1;
        }
    }

    return 0;
}

/*
 * Function: http_cmd_lookup_find(CMD_LOOKUP *CmdLookup,
 *                                  char *ip, int len,
 *                                  int *iError)
 *
 * Purpose: Find a cmd configuration given a IP.
 *          We look up a cmd configuration given an HTTP cmd and
 *          return a pointer to that cmd configuration if found.
 *
 * Arguments: CmdLookup    => a pointer to the lookup structure
 *            cmd          => the http cmd
 *            len          => Length of the cmd
 *            iError       => a pointer to an error code
 *
 * Returns: int => return code indicating error or success
 *
 * Returns: HTTP_CMD_CONF* => Pointer to cmd configuration structure
 *                            matching IP if found, NULL otherwise.
 *
 */
HTTP_CMD_CONF* http_cmd_lookup_find(CMD_LOOKUP* CmdLookup,
    const char* cmd, int len, int* iError)
{
    HTTP_CMD_CONF* HTTPCmd = NULL;

    if (!iError)
    {
        return NULL;
    }

    if (!CmdLookup)
    {
        *iError = -1;
        return NULL;
    }

    *iError = 0;

    HTTPCmd = (HTTP_CMD_CONF*)KMapFind(CmdLookup,(void*)cmd,len);
    if (!HTTPCmd)
    {
        *iError = -1;
    }

    return HTTPCmd;
}

/*
 * Function: http_cmd_lookup_first(CMD_LOOKUP *CmdLookup,
 *                                   int *iError)
 *
 * Purpose: This lookups the first cmd configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: CmdLookup     => pointer to the cmd lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: HTTP_CMD_CONF* => Pointer to first cmd configuration structure
 *
 */
HTTP_CMD_CONF* http_cmd_lookup_first(CMD_LOOKUP* CmdLookup,
    int* iError)
{
    HTTP_CMD_CONF* HTTPCmd;

    if (!iError)
    {
        return NULL;
    }

    if (!CmdLookup)
    {
        *iError = -1;
        return NULL;
    }

    *iError = 0;

    HTTPCmd = (HTTP_CMD_CONF*)KMapFindFirst(CmdLookup);
    if (!HTTPCmd)
    {
        *iError = -1;
    }

    return HTTPCmd;
}

/*
 * Function: http_cmd_lookup_next(CMD_LOOKUP *CmdLookup,
 *                                  int *iError)
 *
 * Iterates to the next configuration, like a list it just returns
 * the next config in the config list.
 *
 * Purpose: This lookups the next cmd configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: CmdLookup     => pointer to the cmd lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: HTTP_CMD_CONF*  => Pointer to next cmd configuration structure
 *
 */
HTTP_CMD_CONF* http_cmd_lookup_next(CMD_LOOKUP* CmdLookup,
    int* iError)
{
    HTTP_CMD_CONF* HTTPCmd;

    if (!iError)
    {
        return NULL;
    }

    if (!CmdLookup)
    {
        *iError = -1;
        return NULL;
    }

    *iError = 0;

    HTTPCmd = (HTTP_CMD_CONF*)KMapFindNext(CmdLookup);
    if (!HTTPCmd)
    {
        *iError = -1;
    }

    return HTTPCmd;
}

