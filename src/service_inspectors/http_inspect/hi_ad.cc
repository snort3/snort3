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

/*
**  @file       hi_ad.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This is the server anomaly module file.  Looks for anomalous
**              servers and other stuff.  Still thinking about it.
**
**  NOTES:
**    - 3.2.03:  Initial development.  DJR
*/
#include <stdlib.h>
#include <sys/types.h>

#include "hi_ui_config.h"
#include "hi_return_codes.h"
#include "hi_si.h"

/*
**  NAME
**    hi_server_anomaly_detection::
*/
/**
**  Inspect packet/streams for anomalous server detection and tunneling.
**
**  This really checks for anything that we want to look at for rogue
**  HTTP servers, HTTP tunneling in unknown servers, and detection of
**  sessions that are actually talking HTTP.
**
**  @param session pointer to the session there is no server conf
**  @param data    unsigned char to payload/stream data
**  @param dsize   the size of the payload/stream data
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
*/
int hi_server_anomaly_detection(void* S, const u_char* data, int dsize)
{
    HI_SESSION* session = (HI_SESSION*)S;
    HTTPINSPECT_GLOBAL_CONF* GlobalConf;

    if (data == NULL || dsize < 1)
        return HI_INVALID_ARG;

    GlobalConf = session->global_conf;

    /*
    **  We are just going to look for server responses on non-HTTP
    **  ports.
    */
    if (GlobalConf->anomalous_servers && dsize > 5)
    {
        /*
        **  We now do the checking for anomalous HTTP servers
        */
        if (data[0]=='H' && data[1]=='T' && data[2]=='T' && data[3]=='P' &&
            data[4]=='/')
        {
            hi_set_event(GID_HTTP_SERVER, HI_ANOM_SERVER);
        }
    }

    return HI_SUCCESS;
}

