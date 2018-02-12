//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// client_app_ym.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_app_ym.h"

#include "app_info_table.h"
#include "application_ids.h"

#define MAX_VERSION_SIZE    64
static const uint8_t APP_YMSG[] = "YMSG";

YmDetector::YmDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "YM";
    proto = IpProtocol::TCP;
    minimum_matches = 1;
    provides_user = true;

    tcp_patterns =
    {
        { APP_YMSG, sizeof(APP_YMSG) - 1, -1, 0, APP_ID_YAHOO_MSG },
    };

    appid_registry =
    {
        { APP_ID_YAHOO, APPINFO_FLAG_CLIENT_ADDITIONAL },
        { APP_ID_YAHOO_MSG, APPINFO_FLAG_CLIENT_ADDITIONAL }
    };

    handler->register_detector(name, this, proto);
}


static const uint8_t* skip_separator(const uint8_t* data, const uint8_t* end)
{
    while ( data + 1 < end  )
    {
        if ( data[0] == 0xc0 && data[1] == 0x80 )
            break;

        data++;
    }

    data += 2;

    return data;
}

int YmDetector::validate(AppIdDiscoveryArgs& args)
{
#define HEADERSIZE 20
#define VERSIONID "135"
#define SEPARATOR 0xc080

    const uint8_t* end;
    uint16_t len;
    uint8_t version[MAX_VERSION_SIZE];
    uint8_t* v;
    uint8_t* v_end;
    uint32_t product_id;

    product_id = APP_ID_YAHOO;
    memset(&version,0,sizeof(version));

    if ( !args.data )
        return APPID_ENULL;

    if (args.dir != APP_ID_FROM_INITIATOR)
        return APPID_INPROCESS;

    /* Validate the packet using the length field, otherwise abort. */
    if ( args.size < 10 )
        return APPID_ENULL;

    len = *((const uint16_t*)(args.data + 8));
    len = ntohs(len);

    if ( len != (args.size - HEADERSIZE) )
        return APPID_ENULL;

    end = args.data + args.size;

    if ( args.size >= HEADERSIZE )
    {
        args.data += HEADERSIZE;
    }

    while ( args.data < end )
    {
        if ( end-args.data >= (int)sizeof(VERSIONID) && memcmp(args.data, VERSIONID,
            sizeof(VERSIONID)-1) ==
            0 )
        {
            args.data += sizeof(VERSIONID)-1;

            if ( args.data + 2 >= end )  /* Skip the separator */
                goto done;
            else
                args.data += 2;

            product_id = APP_ID_YAHOO;

            v = version;

            v_end = v + (MAX_VERSION_SIZE - 1);

            /* Get the version */
            while ( args.data + 1 < end && v < v_end )
            {
                if ( args.data[0] == 0xc0 && args.data[1] == 0x80 )
                    break;

                *v = *args.data;
                v++;
                args.data++;
            }

            goto done;
        }

        args.data = skip_separator(args.data,end); /*skip to the command end separator */
        args.data = skip_separator(args.data,end); /* skip to the command data end separator */
    }

    return APPID_INPROCESS;

done:
    add_app(args.asd, APP_ID_YAHOO, product_id, (char*)version);
    return APPID_SUCCESS;
}

