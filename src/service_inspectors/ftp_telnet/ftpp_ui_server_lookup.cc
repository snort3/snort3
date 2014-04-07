/*
 * ftpp_ui_server_lookup.c
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 * Steven A. Sturges <ssturges@sourcefire.com>
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
 * This file contains functions to access the SERVER_LOOKUP structure.
 *
 * We wrap the access to SERVER_LOOKUP so changing the lookup algorithms
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

static void serverConfFree(void *pData);

/*
 * Function: ftpp_ui_server_lookup_init(SERVER_LOOKUP **ServerLookup)
 *
 * Purpose: Initialize the server_lookup structure.
 *
 *          We need to initialize the server_lookup structure for
 *          the FTP server configuration.  Don't want a NULL pointer
 *          flying around, when we have to look for server configs.
 *
 * Arguments: ServerLookup      => pointer to the pointer of the server
 *                                 lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
#define FTPP_UI_CONFIG_MAX_SERVERS 20
int ftpp_ui_server_lookup_init(SERVER_LOOKUP **ServerLookup)
{
    *ServerLookup =  sfrt_new(DIR_16_4x4_16x5_4x4, IPv6, FTPP_UI_CONFIG_MAX_SERVERS, 20);

    if(*ServerLookup == NULL)
    {
        return FTPP_MEM_ALLOC_FAIL;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_server_lookup_cleanup(SERVER_LOOKUP **ServerLookup)
 *
 * Purpose: Free the server_lookup structure.
 *          We need to free the server_lookup structure.
 *
 * Arguments: ServerLookup  => pointer to the pointer of the server
 *                             lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_server_lookup_cleanup(SERVER_LOOKUP **ServerLookup)
{
    if ((ServerLookup == NULL) || (*ServerLookup == NULL))
        return FTPP_INVALID_ARG;

    sfrt_cleanup(*ServerLookup, serverConfFree);
    sfrt_free(*ServerLookup);
    *ServerLookup = NULL;

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_server_lookup_add(SERVER_LOOKUP *ServerLookup,
 *                                 char *ip, int len,
 *                                 FTP_SERVER_PROTO_CONF *ServerConf)
 *
 * Purpose: Add a server configuration to the list.
 *          We add these keys like you would normally think to add
 *          them, because on low endian machines the least significant
 *          byte is compared first.  This is what we want to compare
 *          IPs backward, doesn't work on high endian machines, but oh
 *          well.  Our platform is Intel.
 *
 * Arguments: ServerLookup => a pointer to the lookup structure
 *            IP           => the ftp server address
 *            len          => Length of the address
 *            ServerConf   => a pointer to the server configuration structure
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_server_lookup_add(
    SERVER_LOOKUP *ServerLookup, sfip_t* Ip, FTP_SERVER_PROTO_CONF *ServerConf )
{
    int iRet;

    if(!ServerLookup || !ServerConf)
    {
        return FTPP_INVALID_ARG;
    }

    iRet = sfrt_insert((void *)Ip, (unsigned char)Ip->bits, (void *)ServerConf, RT_FAVOR_SPECIFIC, ServerLookup);

    if (iRet)
    {
        return FTPP_MEM_ALLOC_FAIL;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_server_lookup_find(SERVER_LOOKUP *ServerLookup,
 *                                  snort_ip_p ip, int *iError)
 *
 * Purpose: Find a server configuration given a IP.
 *          We look up a server configuration given an IP and
 *          return a pointer to that server configuration if found.
 *
 * Arguments: ServerLookup => a pointer to the lookup structure
 *            IP           => the ftp server address
 *            iError       => a pointer to an error code
 *
 * Returns: int => return code indicating error or success
 *
 * Returns: FTP_SERVER_PROTO_CONF* => Pointer to server configuration
 *                            structure matching IP if found, NULL otherwise.
 *
 */
FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_find(
    SERVER_LOOKUP *ServerLookup, snort_ip_p Ip, int *iError
)
{
    FTP_SERVER_PROTO_CONF *ServerConf = NULL;

    if(!iError)
    {
        return NULL;
    }

    if(!ServerLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    ServerConf = (FTP_SERVER_PROTO_CONF *)sfrt_lookup((void *)Ip, ServerLookup);
    if (!ServerConf)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ServerConf;
}


/**Iterate over all the stored IP addresses, calling the callback for
 * all elements.
 *
 * @param ServerLookup => a pointer to the lookup structure
 * @param userfunc => user defined callback function
 * @param iError => a pointer to an error code
 *
 * @returns iError => return code indicating error or success
 *
 */
int ftpp_ui_server_iterate(
    SnortConfig* sc,SERVER_LOOKUP *ServerLookup,
    sfrt_sc_iterator_callback3 userfunc,
    int *iError
    )
{
    if(!iError)
    {
        return 0;
    }

    if(!ServerLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return 0;
    }

    *iError = FTPP_SUCCESS;

    return sfrt_iterate2_with_snort_config(sc, ServerLookup, userfunc);
}

#if 0
/** Obsoleted. After changing underlying KMAP to SFRT. SFRT provides an iterator with
 * a callback function but does not support getFirst, getNext operations.
 */

/*
 * Function: ftpp_ui_server_lookup_first(SERVER_LOOKUP *ServerLookup,
 *                                   int *iError)
 *
 * Purpose: This lookups the first server configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: ServerLookup  => pointer to the server lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_SERVER_PROTO_CONF* => Pointer to first server
 *                                    configuration structure
 *
 */
FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_first(SERVER_LOOKUP *ServerLookup,
                                            int *iError)
{
    FTP_SERVER_PROTO_CONF *ServerConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ServerLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    ServerConf = (FTP_SERVER_PROTO_CONF *)KMapFindFirst(ServerLookup);
    if (!ServerConf)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ServerConf;
}

/*
 * Function: ftpp_ui_server_lookup_next(SERVER_LOOKUP *ServerLookup,
 *                                  int *iError)
 *
 * Iterates to the next configuration, like a list it just returns
 * the next config in the config list.
 *
 * Purpose: This lookups the next server configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: ServerLookup  => pointer to the server lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_SERVER_PROTO_CONF*  => Pointer to next server configuration
 *                             structure
 *
 */
FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_next(SERVER_LOOKUP *ServerLookup,
                                           int *iError)
{
    FTP_SERVER_PROTO_CONF *ServerConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ServerLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    ServerConf = (FTP_SERVER_PROTO_CONF *)KMapFindNext(ServerLookup);
    if (!ServerConf)
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ServerConf;
}
#endif

/**Free pData buffer, which may be referenced multiple times. ReferenceCount
 * is the number of times the buffer is referenced.  For freeing the buffer,
 * we just decrement referenceCount till it reaches 0, at which time the
 * buffer is also freed.
 */
static void serverConfFree(void *pData)
{
    FTP_SERVER_PROTO_CONF *serverConf = (FTP_SERVER_PROTO_CONF *)pData;

    if (serverConf)
    {
        serverConf->referenceCount--;
        if (serverConf->referenceCount == 0)
        {
            FTPTelnetCleanupFTPServerConf((void *)serverConf);
            free(serverConf);
        }
    }
}

