/*
 * ftpp_ui_client_lookup.c
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 * Kevin Liu <kliu@sourcefire.com>
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
 * Description:
 *
 * This file contains functions to access the CLIENT_LOOKUP structure.
 *
 * We wrap the access to CLIENT_LOOKUP so changing the lookup algorithms
 * are more modular and independent.  This is the only file that would need
 * to be changed to change the algorithmic lookup.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hi_util_kmap.h"
#include "ftpp_ui_config.h"
#include "ftpp_return_codes.h"
#include "ft_main.h"
#include "sfrt/sfrt.h"

static void clientConfFree(void *pData);

/*
 * Function: ftpp_ui_client_lookup_init(CLIENT_LOOKUP **ClientLookup)
 *
 * Purpose: Initialize the client_lookup structure.
 *
 *          We need to initialize the client_lookup structure for
 *          the FTP client configuration.  Don't want a NULL pointer
 *          flying around, when we have to look for FTP clients.
 *
 * Arguments: ClientLookup      => pointer to the pointer of the client
 *                                 lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
#define FTPP_UI_CONFIG_MAX_CLIENTS 20
int ftpp_ui_client_lookup_init(CLIENT_LOOKUP **ClientLookup)
{
    *ClientLookup =  sfrt_new(DIR_16_4x4_16x5_4x4, IPv6, FTPP_UI_CONFIG_MAX_CLIENTS, 20);

    if(*ClientLookup == NULL)
    {
        return FTPP_MEM_ALLOC_FAIL;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_client_lookup_cleanup(CLIENT_LOOKUP **ClientLookup)
 *
 * Purpose: Free the client_lookup structure.
 *          We need to free the client_lookup structure.
 *
 * Arguments: ClientLookup  => pointer to the pointer of the client
 *                             lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_client_lookup_cleanup(CLIENT_LOOKUP **ClientLookup)
{
    if ((ClientLookup == NULL) || (*ClientLookup == NULL))
        return FTPP_INVALID_ARG;

    sfrt_cleanup(*ClientLookup, clientConfFree);
    sfrt_free(*ClientLookup);
    *ClientLookup = NULL;

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_client_lookup_add(CLIENT_LOOKUP *ClientLookup,
 *                                 sfip_t* Ip, 
 *                                 FTP_CLIENT_PROTO_CONF *ClientConf)
 *
 * Purpose: Add a client configuration to the list.
 *          We add these keys like you would normally think to add
 *          them, because on low endian machines the least significant
 *          byte is compared first.  This is what we want to compare
 *          IPs backward, doesn't work on high endian machines, but oh
 *          well.  Our platform is Intel.
 *
 * Arguments: ClientLookup => a pointer to the lookup structure
 *            IP           => the ftp client address
 *            ClientConf   => a pointer to the client configuration structure
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_client_lookup_add(
    CLIENT_LOOKUP *ClientLookup,
    sfip_t* Ip, FTP_CLIENT_PROTO_CONF *ClientConf)
{
    int iRet;

    if(!ClientLookup || !ClientConf)
    {
        return FTPP_INVALID_ARG;
    }

    iRet = sfrt_insert((void *)Ip, (unsigned char)Ip->bits,
        (void *)ClientConf, RT_FAVOR_SPECIFIC, ClientLookup);

    if (iRet)
    {
        /*
         * This means the key has already been added.
         */
        if(iRet == 1)
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
 * Function: ftpp_ui_client_lookup_find(CLIENT_LOOKUP *ClientLookup,
 *                                  snort_ip_p ip, int *iError)
 *
 * Purpose: Find a client configuration given a IP.
 *          We look up a client configuration given an IP and
 *          return a pointer to that client configuration if found.
 *
 * Arguments: ClientLookup => a pointer to the lookup structure
 *            IP           => the ftp client address
 *            iError       => a pointer to an error code
 *
 * Returns: int => return code indicating error or success
 *
 * Returns: FTP_CLIENT_PROTO_CONF* => Pointer to client configuration
 *                           structure matching IP if found, NULL otherwise.
 *
 */

FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_find(CLIENT_LOOKUP *ClientLookup,
                                            snort_ip_p Ip, int *iError)
{
    FTP_CLIENT_PROTO_CONF *ClientConf = NULL;

    if(!iError)
    {
        return NULL;
    }

    if(!ClientLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    ClientConf = (FTP_CLIENT_PROTO_CONF *)sfrt_lookup((void *)Ip, ClientLookup);
    if (!ClientConf)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ClientConf;
}

#if 0
/** Obsoleted. After changing underlying KMAP to SFRT. SFRT provides an iterator with
 * a callback function but does not support getFirst, getNext operations.
 */
/*
 * Function: ftpp_ui_client_lookup_first(CLIENT_LOOKUP *ClientLookup,
 *                                   int *iError)
 *
 * Purpose: This lookups the first client configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: ClientLookup  => pointer to the client lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_CLIENT_PROTO_CONF* => Pointer to first client configuration
 *                             structure
 *
 */
FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_first(CLIENT_LOOKUP *ClientLookup,
                                            int *iError)
{
    FTP_CLIENT_PROTO_CONF *ClientConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ClientLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    ClientConf = (FTP_CLIENT_PROTO_CONF *)KMapFindFirst(ClientLookup);
    if (!ClientConf)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ClientConf;
}

/*
 * Function: ftpp_ui_client_lookup_next(CLIENT_LOOKUP *ClientLookup,
 *                                  int *iError)
 *
 * Iterates to the next configuration, like a list it just returns
 * the next config in the config list.
 *
 * Purpose: This lookups the next client configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: ClientLookup  => pointer to the client lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_CLIENT_PROTO_CONF*  => Pointer to next client configuration
 *                             structure
 *
 */
FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_next(CLIENT_LOOKUP *ClientLookup,
                                           int *iError)
{
    FTP_CLIENT_PROTO_CONF *ClientConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ClientLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    ClientConf = (FTP_CLIENT_PROTO_CONF *)KMapFindNext(ClientLookup);
    if (!ClientConf)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ClientConf;
}
#endif

/**Free pData buffer, which may be referenced multiple times. ReferenceCount
 * is the number of times the buffer is referenced.  For freeing the buffer,
 * we just decrement referenceCount till it reaches 0, at which time the
 * buffer is also freed.
 */
static void clientConfFree(void *pData)
{
    FTP_CLIENT_PROTO_CONF *clientConf = (FTP_CLIENT_PROTO_CONF *)pData;

    if (clientConf)
    {
        clientConf->referenceCount--;
        if (clientConf->referenceCount == 0)
        {
            FTPTelnetCleanupFTPClientConf((void *)clientConf);
            free(clientConf);
        }
    }
}

