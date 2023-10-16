//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <cassert>

#include "ft_main.h"
#include "ftpp_return_codes.h"

using namespace snort;

int ftp_bounce_lookup_init(BOUNCE_LOOKUP** BounceLookup)
{
    *BounceLookup = KMapNew((KMapUserFreeFunc)CleanupFTPBounceTo, true);
    return FTPP_SUCCESS;
}

int ftp_bounce_lookup_cleanup(BOUNCE_LOOKUP** BounceLookup)
{
    assert(BounceLookup);

    if ( *BounceLookup )
    {
        KMapDelete(*BounceLookup);
        *BounceLookup = nullptr;
    }
    return FTPP_SUCCESS;
}

int ftp_bounce_lookup_add(BOUNCE_LOOKUP* BounceLookup, const SfIp* Ip,
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

FTP_BOUNCE_TO* ftp_bounce_lookup_find(BOUNCE_LOOKUP* BounceLookup, const SfIp* Ip,
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

FTP_BOUNCE_TO* ftp_bounce_lookup_first(BOUNCE_LOOKUP* BounceLookup, int* iError)
{
    FTP_BOUNCE_TO* BounceTo;

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

    BounceTo = (FTP_BOUNCE_TO*)KMapFindFirst(BounceLookup);
    if (!BounceTo)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return BounceTo;
}

FTP_BOUNCE_TO* ftp_bounce_lookup_next(BOUNCE_LOOKUP* BounceLookup, int* iError)
{
    FTP_BOUNCE_TO* BounceTo;

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

    BounceTo = (FTP_BOUNCE_TO*)KMapFindNext(BounceLookup);
    if (!BounceTo)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return BounceTo;
}
