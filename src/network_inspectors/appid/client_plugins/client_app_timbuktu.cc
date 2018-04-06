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

// client_app_timbuktu.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_app_timbuktu.h"

#include "protocols/packet.h"
#include "utils/sflsq.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "application_ids.h"

static const char TIMBUKTU_BANNER[] = "\000\001";

#define TIMBUKTU_BANNER_LEN (sizeof(TIMBUKTU_BANNER)-1)
#define MAX_ANY_SIZE    2

enum TIMBUKTUState
{
    TIMBUKTU_STATE_BANNER = 0,
    TIMBUKTU_STATE_ANY_MESSAGE_LEN,
    TIMBUKTU_STATE_MESSAGE_LEN,
    TIMBUKTU_STATE_MESSAGE_DATA
};

struct ClientTIMBUKTUData
{
    TIMBUKTUState state;
    uint16_t stringlen;
    unsigned pos;
    union
    {
        uint16_t len;
        uint8_t raw_len[2];
    } l;
};

#pragma pack(1)
struct ClientTIMBUKTUMsg
{
    uint16_t len;
    uint8_t message;
};
#pragma pack()

TimbuktuClientDetector::TimbuktuClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "TIMBUKTU";
    proto = IpProtocol::TCP;
    minimum_matches = 1;
    provides_user = true;

    tcp_patterns =
    {
        { (const uint8_t*)TIMBUKTU_BANNER, sizeof(TIMBUKTU_BANNER)-1, 0, 0, APP_ID_TIMBUKTU },
    };

    appid_registry =
    {
        { APP_ID_TIMBUKTU, 0 }
    };

    handler->register_detector(name, this, proto);
}


int TimbuktuClientDetector::validate(AppIdDiscoveryArgs& args)
{
    ClientTIMBUKTUData* fd;
    uint16_t offset;

    if (args.dir != APP_ID_FROM_INITIATOR)
        return APPID_INPROCESS;

    fd = (ClientTIMBUKTUData*)data_get(args.asd);
    if (!fd)
    {
        fd = (ClientTIMBUKTUData*)snort_calloc(sizeof(ClientTIMBUKTUData));
        data_add(args.asd, fd, &snort_free);
        fd->state = TIMBUKTU_STATE_BANNER;
    }

    offset = 0;
    while (offset < args.size)
    {
        switch (fd->state)
        {
        case TIMBUKTU_STATE_BANNER:
            if (args.data[offset] != TIMBUKTU_BANNER[fd->pos])
                return APPID_EINVALID;
            if (fd->pos >= TIMBUKTU_BANNER_LEN-1)
            {
                fd->pos = 0;
                fd->state = TIMBUKTU_STATE_ANY_MESSAGE_LEN;
                break;
            }
            fd->pos++;
            break;
        /* check any 2 bytes first */
        case TIMBUKTU_STATE_ANY_MESSAGE_LEN:
            fd->pos++;
            if (fd->pos >= MAX_ANY_SIZE)
            {
                fd->pos = 0;
                fd->state = TIMBUKTU_STATE_MESSAGE_LEN;
                break;
            }
            break;
        case TIMBUKTU_STATE_MESSAGE_LEN:
            if (fd->pos < offsetof(ClientTIMBUKTUMsg, message))
            {
                fd->l.raw_len[fd->pos] = args.data[offset];
            }
            fd->pos++;
            if (fd->pos >= offsetof(ClientTIMBUKTUMsg, message))
            {
                fd->stringlen = ntohs(fd->l.len);
                if (!fd->stringlen)
                {
                    if (offset == args.size - 1)
                        goto done;
                    return APPID_EINVALID;
                }
                else if ((fd->stringlen + TIMBUKTU_BANNER_LEN + MAX_ANY_SIZE + offsetof(
                    ClientTIMBUKTUMsg, message)) > args.size)
                    return APPID_EINVALID;
                fd->state = TIMBUKTU_STATE_MESSAGE_DATA;
                fd->pos = 0;
            }
            break;
        case TIMBUKTU_STATE_MESSAGE_DATA:
            fd->pos++;
            if (fd->pos == fd->stringlen)
            {
                if (offset == args.size - 1)
                    goto done;
                return APPID_EINVALID;
            }
            break;
        default:
            goto inprocess;
        }
        offset++;
    }
inprocess:
    return APPID_INPROCESS;

done:
    add_app(args.asd, APP_ID_TIMBUKTU, APP_ID_TIMBUKTU, nullptr);
    return APPID_SUCCESS;
}

