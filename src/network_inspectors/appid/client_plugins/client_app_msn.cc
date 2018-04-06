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

// client_app_msn.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "client_app_msn.h"

#include "app_info_table.h"

#define MAX_VERSION_SIZE 64

static const uint8_t VER[] = "VER ";
static const uint8_t CVRMAIN[] = "CVR0\x00d\x00a";
static const uint8_t CVR[] = "CVR";
static const uint8_t MSNMSGR[] = "MSNMSGR";
static const uint8_t MACMSGS[] = "macmsgs";
static const uint8_t MSMSGS[] = "MSMSGS";

MsnClientDetector::MsnClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "MSN";
    proto = IpProtocol::TCP;
    minimum_matches = 2;

    tcp_patterns =
    {
        { VER,     sizeof(VER)-1,     -1, 0, APP_ID_MSN },
        { CVRMAIN, sizeof(CVRMAIN)-1, -1, 0, APP_ID_MSN },
        { MSNMSGR, sizeof(MSNMSGR)-1, -1, 0, APP_ID_MSN_MESSENGER },
        { MACMSGS, sizeof(MACMSGS)-1, -1, 0, APP_ID_MSN_MESSENGER },
        { MSMSGS,  sizeof(MSMSGS)-1,  -1, 0, APP_ID_MICROSOFT_WINDOWS_MESSENGER }
    };

    appid_registry =
    {
        { APP_ID_MICROSOFT_WINDOWS_MESSENGER, APPINFO_FLAG_CLIENT_ADDITIONAL },
        { APP_ID_MSN_MESSENGER, APPINFO_FLAG_CLIENT_ADDITIONAL },
        { APP_ID_MSN, APPINFO_FLAG_CLIENT_ADDITIONAL },
        { APP_ID_MSNP, APPINFO_FLAG_CLIENT_ADDITIONAL }
    };

    handler->register_detector(name, this, proto);
}


int MsnClientDetector::validate(AppIdDiscoveryArgs& args)
{
    const uint8_t* end;
    uint8_t version[MAX_VERSION_SIZE];
    uint8_t* v;
    uint8_t* v_end;
    uint32_t product_id;

    product_id = APP_ID_MSN_MESSENGER;
    memset(&version,0,sizeof(version));

    if (!args.data)
        return APPID_ENULL;

    if (args.dir != APP_ID_FROM_INITIATOR)
        return APPID_INPROCESS;

    if (args.size >= sizeof(CVR) && memcmp(args.data, CVR, sizeof(CVR)-1) == 0)
    {
        int space_count = 0;

        end = args.data + args.size;

        while ( args.data < end && space_count < 6 ) /* Skip to the product and version strings */
        {
            if ( *args.data == ' ' )
                space_count++;

            args.data++;
        }

        /* Get the product */
        if ( end - args.data >= (int)sizeof(MSNMSGR) && memcmp(args.data, MSNMSGR, sizeof(MSNMSGR)-
            1) == 0 )
        {
            product_id = APP_ID_MSN_MESSENGER;
            args.data += sizeof(MSNMSGR) - 1;

            args.data++; /* skip the space */
        }
        else if ( end - args.data >= (int)sizeof(MACMSGS) &&
            memcmp(args.data, MACMSGS, sizeof(MACMSGS)-1) == 0 )
        {
            product_id = APP_ID_MSN_MESSENGER;
            args.data += sizeof(MACMSGS) - 1;

            args.data++; /* skip the space */
        }
        else if ( end - args.data >= (int)sizeof(MSMSGS) &&
            memcmp(args.data, MSMSGS, sizeof(MSMSGS)-1) == 0 )
        {
            product_id = APP_ID_MICROSOFT_WINDOWS_MESSENGER;
            args.data += sizeof(MSMSGS) - 1;

            args.data++;         /* skip the space */
        }
        else /* advance past the unknown product name */
        {
            while ( args.data < end && *args.data != ' ')
                args.data++;

            args.data++; /* skip the space */
        }

        v = version;

        v_end = v + (MAX_VERSION_SIZE - 1);

        /* Get the version */
        while ( args.data < end && *args.data != ' ' && v < v_end )
        {
            *v = *args.data;
            v++;
            args.data++;
        }

        goto done;
    }

    return APPID_INPROCESS;

done:
    add_app(args.asd, APP_ID_MSN_MESSENGER, product_id, (char*)version);
    return APPID_SUCCESS;
}

