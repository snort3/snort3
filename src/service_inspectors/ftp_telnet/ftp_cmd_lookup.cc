//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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
 * Description:
 *
 * This file contains functions to access the CMD_LOOKUP structure.
 *
 * We wrap the access to CMD_LOOKUP so changing the lookup algorithms
 * are more modular and independent.  This is the only file that would need
 * to be changed to change the algorithmic lookup.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 * Kevin Liu <kliu@sourcefire.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftp_cmd_lookup.h"

#include "ft_main.h"
#include "ftpp_return_codes.h"

using namespace snort;

/*
 * Function: ftp_cmd_lookup_init(CMD_LOOKUP **CmdLookup)
 *
 * Purpose: Initialize the cmd_lookup structure.
 *
 *          We need to initialize the cmd_lookup structure for
 *          the FTP command configuration.  Don't want a NULL pointer
 *          flying around, when we have to look for FTP commands.
 *
 * Arguments: CmdLookup         => pointer to the pointer of the cmd
 *                                 lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftp_cmd_lookup_init(CMD_LOOKUP** CmdLookup)
{
    KMAP* km = KMapNew((KMapUserFreeFunc)CleanupFTPCMDConf);
    *CmdLookup = km;
    if (*CmdLookup == nullptr)
    {
        return FTPP_MEM_ALLOC_FAIL;
    }

    km->nocase = 1;

    return FTPP_SUCCESS;
}

/*
 * Function: ftp_cmd_lookup_cleanup(CMD_LOOKUP **CmdLookup)
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
int ftp_cmd_lookup_cleanup(CMD_LOOKUP** CmdLookup)
{
    KMAP* km;

    if (CmdLookup == nullptr)
        return FTPP_INVALID_ARG;

    km = *CmdLookup;

    if (km)
    {
        KMapDelete(km);
        *CmdLookup = nullptr;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftp_cmd_lookup_add(CMD_LOOKUP *CmdLookup,
 *                                 char *ip, int len,
 *                                 FTP_CMD_CONF *FTPCmd)
 *
 * Purpose: Add a cmd configuration to the list.
 *          We add these keys like you would normally think to add
 *          them, because on low endian machines the least significant
 *          byte is compared first.  This is what we want to compare
 *          IPs backward, doesn't work on high endian machines, but oh
 *          well.  Our platform is Intel.  FIXIT-L say what? endian madness
 *
 * Arguments: CmdLookup    => a pointer to the lookup structure
 *            cmd          => the ftp cmd
 *            len          => Length of the cmd
 *            FTPCmd       => a pointer to the cmd configuration structure
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftp_cmd_lookup_add(CMD_LOOKUP* CmdLookup, const char* cmd, int len,
    FTP_CMD_CONF* FTPCmd)
{
    int iRet;

    if (!CmdLookup || !FTPCmd)
    {
        return FTPP_INVALID_ARG;
    }

    iRet = KMapAdd(CmdLookup, (void*)cmd, len, (void*)FTPCmd);
    if (iRet)
    {
        /*
         * This means the key has already been added.
         */
        if (iRet == 1)
        {
            return FTPP_NONFATAL_ERR;
        }
        else
        {
            return FTPP_MEM_ALLOC_FAIL;
        }
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftp_cmd_lookup_find(CMD_LOOKUP *CmdLookup,
 *                                  char *ip, int len,
 *                                  int *iError)
 *
 * Purpose: Find a cmd configuration given a IP.
 *          We look up a cmd configuration given an FTP cmd and
 *          return a pointer to that cmd configuration if found.
 *
 * Arguments: CmdLookup    => a pointer to the lookup structure
 *            cmd          => the ftp cmd
 *            len          => Length of the cmd
 *            iError       => a pointer to an error code
 *
 * Returns: int => return code indicating error or success
 *
 * Returns: FTP_CMD_CONF* => Pointer to cmd configuration structure
 *                            matching IP if found, NULL otherwise.
 *
 */
FTP_CMD_CONF* ftp_cmd_lookup_find(CMD_LOOKUP* CmdLookup,
    const char* cmd, int len, int* iError)
{
    FTP_CMD_CONF* FTPCmd = nullptr;

    if (!iError)
    {
        return nullptr;
    }

    if (!CmdLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return nullptr;
    }

    *iError = FTPP_SUCCESS;

    FTPCmd = (FTP_CMD_CONF*)KMapFind(CmdLookup,(void*)cmd,len);
    if (!FTPCmd)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return FTPCmd;
}

/*
 * Function: ftp_cmd_lookup_first(CMD_LOOKUP *CmdLookup,
 *                                   int *iError)
 *
 * Purpose: This lookups the first cmd configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: CmdLookup     => pointer to the cmd lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_CMD_CONF* => Pointer to first cmd configuration structure
 *
 */
FTP_CMD_CONF* ftp_cmd_lookup_first(CMD_LOOKUP* CmdLookup,
    int* iError)
{
    FTP_CMD_CONF* FTPCmd;

    if (!iError)
    {
        return nullptr;
    }

    if (!CmdLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return nullptr;
    }

    *iError = FTPP_SUCCESS;

    FTPCmd = (FTP_CMD_CONF*)KMapFindFirst(CmdLookup);
    if (!FTPCmd)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return FTPCmd;
}

/*
 * Function: ftp_cmd_lookup_next(CMD_LOOKUP *CmdLookup,
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
 * Returns: FTP_CMD_CONF*  => Pointer to next cmd configuration structure
 *
 */
FTP_CMD_CONF* ftp_cmd_lookup_next(CMD_LOOKUP* CmdLookup,
    int* iError)
{
    FTP_CMD_CONF* FTPCmd;

    if (!iError)
    {
        return nullptr;
    }

    if (!CmdLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return nullptr;
    }

    *iError = FTPP_SUCCESS;

    FTPCmd = (FTP_CMD_CONF*)KMapFindNext(CmdLookup);
    if (!FTPCmd)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return FTPCmd;
}

