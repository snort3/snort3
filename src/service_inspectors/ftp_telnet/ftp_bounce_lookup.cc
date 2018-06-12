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
 *
 * Description:
 *
 * This file contains functions to access the BOUNCE_LOOKUP structure.
 *
 * We wrap the access to BOUNCE_LOOKUP so changing the lookup algorithms
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

#include "ftp_bounce_lookup.h"

#include "ft_main.h"
#include "ftpp_return_codes.h"

using namespace snort;

/*
 * Function: ftp_bounce_lookup_init(BOUNCE_LOOKUP **BounceLookup)
 *
 * Purpose: Initialize the bounce_lookup structure.
 *
 *          We need to initialize the bounce_lookup structure for
 *          the FTP bounce configuration.  Don't want a NULL pointer
 *          flying around, when we have to look for allowable bounces.
 *
 * Arguments: BounceLookup      => pointer to the pointer of the bounce
 *                                 lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftp_bounce_lookup_init(BOUNCE_LOOKUP** BounceLookup)
{
    KMAP* km = KMapNew((KMapUserFreeFunc)CleanupFTPBounceTo);
    *BounceLookup = km;
    if (*BounceLookup == nullptr)
    {
        return FTPP_MEM_ALLOC_FAIL;
    }

    km->nocase = 1;

    return FTPP_SUCCESS;
}

/*
 * Function: ftp_bounce_lookup_cleanup(BOUNCE_LOOKUP **BounceLookup)
 *
 * Purpose: Free the bounce_lookup structure.
 *          We need to free the bounce_lookup structure.
 *
 * Arguments: BounceLookup  => pointer to the pointer of the bounce
 *                             lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftp_bounce_lookup_cleanup(BOUNCE_LOOKUP** BounceLookup)
{
    KMAP* km;

    if (BounceLookup == nullptr)
        return FTPP_INVALID_ARG;

    km = *BounceLookup;

    if (km)
    {
        KMapDelete(km);
        *BounceLookup = nullptr;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftp_bounce_lookup_add(BOUNCE_LOOKUP *BounceLookup,
 *                                 char *ip, int len,
 *                                 FTP_BOUNCE_TO *BounceTo)
 *
 * Purpose: Add a bounce configuration to the list.  IP is stored
 *          in dot notation order.  When the lookup happens, we
 *          compare up to len bytes of the address.
 *
 * Arguments: BounceLookup => a pointer to the lookup structure
 *            IP           => the ftp bounce address
 *            BounceTo     => a pointer to the bounce configuration structure
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftp_bounce_lookup_add(BOUNCE_LOOKUP* BounceLookup, const snort::SfIp* Ip,
    FTP_BOUNCE_TO* BounceTo)
{
    int iRet;

    if (!BounceLookup || !BounceTo)
    {
        return FTPP_INVALID_ARG;
    }

    iRet = KMapAdd(BounceLookup, (void*)Ip, sizeof(*Ip), (void*)BounceTo);

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
 * Function: ftp_bounce_lookup_find(BOUNCE_LOOKUP *BounceLookup,
 *                                  const SfIp *ip, int *iError)
 *
 * Purpose: Find a bounce configuration given a IP.
 *          We look up a bounce configuration given an IP and
 *          return a pointer to that bounce configuration if found.
 *
 * Arguments: BounceLookup => a pointer to the lookup structure
 *            IP           => the ftp bounce address
 *            iError       => a pointer to an error code
 *
 * Returns: int => return code indicating error or success
 *
 * Returns: FTP_BOUNCE_TO* => Pointer to bounce configuration structure
 *                            matching IP if found, NULL otherwise.
 *
 */
FTP_BOUNCE_TO* ftp_bounce_lookup_find(BOUNCE_LOOKUP* BounceLookup, const snort::SfIp* Ip,
    int* iError)
{
    FTP_BOUNCE_TO* BounceTo = nullptr;

    if (!iError)
    {
        return nullptr;
    }

    if (!BounceLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return nullptr;
    }

    *iError = FTPP_SUCCESS;

    BounceTo = (FTP_BOUNCE_TO*)KMapFind(BounceLookup, (void*)Ip, sizeof(*Ip));
    if (!BounceTo)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return BounceTo;
}

// FIXIT-L orphan code until FTP client inspector acquires a show() method
#if 0
/*
 * Function: ftp_bounce_lookup_first(BOUNCE_LOOKUP *BounceLookup,
 *                                   int *iError)
 *
 * Purpose: This lookups the first bounce configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: BounceLookup  => pointer to the bounce lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_BOUNCE_TO* => Pointer to first bounce configuration structure
 *
 */
FTP_BOUNCE_TO* ftp_bounce_lookup_first(BOUNCE_LOOKUP* BounceLookup, int* iError)
{
    FTP_BOUNCE_TO* BounceTo;

    if (!iError)
    {
        return NULL;
    }

    if (!BounceLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    BounceTo = (FTP_BOUNCE_TO*)KMapFindFirst(BounceLookup);
    if (!BounceTo)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return BounceTo;
}

/*
 * Function: ftp_bounce_lookup_next(BOUNCE_LOOKUP *BounceLookup,
 *                                  int *iError)
 *
 * Iterates to the next configuration, like a list it just returns
 * the next config in the config list.
 *
 * Purpose: This lookups the next bounce configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: BounceLookup  => pointer to the bounce lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_BOUNCE_TO*  => Pointer to next bounce configuration structure
 *
 */
FTP_BOUNCE_TO* ftp_bounce_lookup_next(BOUNCE_LOOKUP* BounceLookup, int* iError)
{
    FTP_BOUNCE_TO* BounceTo;

    if (!iError)
    {
        return NULL;
    }

    if (!BounceLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    BounceTo = (FTP_BOUNCE_TO*)KMapFindNext(BounceLookup);
    if (!BounceTo)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return BounceTo;
}
#endif

