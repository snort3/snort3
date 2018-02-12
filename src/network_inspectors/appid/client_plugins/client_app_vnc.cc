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

// client_app_vnc.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_app_vnc.h"

#include "app_info_table.h"
#include "application_ids.h"

static const char VNC_BANNER[] = "RFB ";
static const char VNC_BANNER2[] = ".";

#define VNC_BANNER_LEN (sizeof(VNC_BANNER)-1)

enum VNCState
{
    VNC_STATE_BANNER = 0,
    VNC_STATE_VERSION
};

#define MAX_VNC_VERSION_SIZE    8
struct ClientVNCData
{
    VNCState state;
    unsigned pos;
    uint8_t version[MAX_VNC_VERSION_SIZE];
};

VncClientDetector::VncClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "RFB";
    proto = IpProtocol::TCP;
    minimum_matches = 2;
    provides_user = true;

    tcp_patterns =
    {
        { (const uint8_t*)VNC_BANNER,  sizeof(VNC_BANNER)-1, -1, 0, APP_ID_VNC },
        { (const uint8_t*)VNC_BANNER2, sizeof(VNC_BANNER2)-1, 7, 0, APP_ID_VNC },
    };

    appid_registry =
    {
        { APP_ID_VNC, APPINFO_FLAG_CLIENT_ADDITIONAL },
        { APP_ID_VNC_RFB, APPINFO_FLAG_CLIENT_ADDITIONAL }
    };

    handler->register_detector(name, this, proto);
}


int VncClientDetector::validate(AppIdDiscoveryArgs& args)
{
    ClientVNCData* fd;
    uint16_t offset;

    if (args.dir != APP_ID_FROM_INITIATOR)
        return APPID_INPROCESS;

    fd = (ClientVNCData*)data_get(args.asd);
    if (!fd)
    {
        fd = (ClientVNCData*)snort_calloc(sizeof(ClientVNCData));
        data_add(args.asd, fd, &snort_free);
        fd->state = VNC_STATE_BANNER;
    }

    offset = 0;
    while (offset < args.size)
    {
        switch (fd->state)
        {
        case VNC_STATE_BANNER:
            if (args.data[offset] != VNC_BANNER[fd->pos])
                return APPID_EINVALID;
            if (fd->pos >= VNC_BANNER_LEN-1)
            {
                fd->state = VNC_STATE_VERSION;
                fd->pos = 0;
                break;
            }
            fd->pos++;
            break;
        case VNC_STATE_VERSION:
            if ((isdigit(args.data[offset]) || args.data[offset] == '.' ||
                args.data[offset] == '\n') && fd->pos < MAX_VNC_VERSION_SIZE)
            {
                fd->version[fd->pos] = args.data[offset];
                if (args.data[offset] == '\n' && fd->pos == 7)
                {
                    fd->version[fd->pos] = 0;
                    goto done;
                }
            }
            else
                return APPID_EINVALID;
            fd->pos++;
            break;
        default:
            goto inprocess;
        }
        offset++;
    }
inprocess:
    return APPID_INPROCESS;

done:
    add_app(args.asd, APP_ID_VNC_RFB, APP_ID_VNC, (const char*)fd->version);
    return APPID_SUCCESS;
}

