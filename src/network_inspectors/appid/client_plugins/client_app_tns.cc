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

// client_app_tns.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_app_tns.h"

#include "app_info_table.h"
#include "application_ids.h"

static const char TNS_BANNER[] = "\000\000";
#define TNS_BANNER_LEN (sizeof(TNS_BANNER)-1)

#define TNS_TYPE_CONNECT 1
#define TNS_TYPE_ACCEPT 2
#define TNS_TYPE_ACK 3
#define TNS_TYPE_REFUSE 4
#define TNS_TYPE_REDIRECT 5
#define TNS_TYPE_DATA 6
#define TNS_TYPE_NULL 7
#define TNS_TYPE_ABORT 9
#define TNS_TYPE_RESEND 11
#define TNS_TYPE_MARKER 12
#define TNS_TYPE_ATTENTION 13
#define TNS_TYPE_CONTROL 14
#define TNS_TYPE_MAX 19

#define CONNECT_VERSION_OFFSET 8
#define CONNECT_DATA_OFFSET 26

#define USER_STRING "user="
#define MAX_USER_POS ((int)sizeof(USER_STRING) - 2)

enum TNSState
{
    TNS_STATE_MESSAGE_LEN = 0,
    TNS_STATE_MESSAGE_CHECKSUM,
    TNS_STATE_MESSAGE,
    TNS_STATE_MESSAGE_RES,
    TNS_STATE_MESSAGE_HD_CHECKSUM,
    TNS_STATE_MESSAGE_DATA,
    TNS_STATE_MESSAGE_CONNECT,
    TNS_STATE_MESSAGE_CONNECT_OFFSET_DC,
    TNS_STATE_MESSAGE_CONNECT_OFFSET,
    TNS_STATE_MESSAGE_CONNECT_PREDATA,
    TNS_STATE_MESSAGE_CONNECT_DATA,
    TNS_STATE_COLLECT_USER
};

struct ClientTNSData
{
    TNSState state;
    unsigned stringlen;
    unsigned offsetlen;
    unsigned pos;
    unsigned message;
    union
    {
        uint16_t len;
        uint8_t raw_len[2];
    } l;
    const char* version;
    uint8_t* data;
};

#pragma pack(1)
struct ClientTNSMsg
{
    uint16_t len;
    uint16_t checksum;
    uint8_t msg;
    uint8_t res;
    uint16_t hdchecksum;
    uint8_t data;
};
#pragma pack()

TnsClientDetector::TnsClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "TNS";
    proto = IpProtocol::TCP;
    minimum_matches = 1;
    provides_user = true;

    tcp_patterns =
    {
        { (const uint8_t*)TNS_BANNER, TNS_BANNER_LEN, 2, 0, APP_ID_ORACLE_DATABASE },
    };

    appid_registry =
    {
        { APP_ID_ORACLE_DATABASE, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER }
    };

    handler->register_detector(name, this, proto);
}


static int reset_flow_data(ClientTNSData* fd)
{
    memset(fd, '\0', sizeof(ClientTNSData));
    fd->state = TNS_STATE_MESSAGE_LEN;
    return APPID_EINVALID;
}

#define TNS_MAX_INFO_SIZE    63
int TnsClientDetector::validate(AppIdDiscoveryArgs& args)
{
    char username[TNS_MAX_INFO_SIZE + 1];
    ClientTNSData* fd;
    uint16_t offset;
    int user_pos = 0;
    int user_size = 0;
    uint16_t user_start = 0;
    uint16_t user_end = 0;

    if (args.dir != APP_ID_FROM_INITIATOR)
        return APPID_INPROCESS;

    fd = (ClientTNSData*)data_get(args.asd);
    if (!fd)
    {
        fd = (ClientTNSData*)snort_calloc(sizeof(ClientTNSData));
        data_add(args.asd, fd, &snort_free);
        fd->state = TNS_STATE_MESSAGE_LEN;
    }

    offset = 0;
    while (offset < args.size)
    {
        switch (fd->state)
        {
        case TNS_STATE_MESSAGE_LEN:
            fd->l.raw_len[fd->pos++] = args.data[offset];
            if (fd->pos >= offsetof(ClientTNSMsg, checksum))
            {
                fd->stringlen = ntohs(fd->l.len);
                if (fd->stringlen == 2)
                {
                    if (offset == args.size - 1)
                        goto done;
                    return reset_flow_data(fd);
                }
                else if (fd->stringlen < 2)
                    return reset_flow_data(fd);
                else if (fd->stringlen > args.size)
                    return reset_flow_data(fd);
                else
                    fd->state = TNS_STATE_MESSAGE_CHECKSUM;
            }
            break;

        case TNS_STATE_MESSAGE_CHECKSUM:
            if (args.data[offset] != 0)
                return reset_flow_data(fd);
            fd->pos++;
            if (fd->pos >= offsetof(ClientTNSMsg, msg))
                fd->state = TNS_STATE_MESSAGE;
            break;

        case TNS_STATE_MESSAGE:
            fd->message = args.data[offset];
            if (fd->message < TNS_TYPE_CONNECT || fd->message > TNS_TYPE_MAX)
                return reset_flow_data(fd);
            fd->pos++;
            fd->state = TNS_STATE_MESSAGE_RES;
            break;
        case TNS_STATE_MESSAGE_RES:
            fd->state = TNS_STATE_MESSAGE_HD_CHECKSUM;
            fd->pos++;
            break;
        case TNS_STATE_MESSAGE_HD_CHECKSUM:
            fd->pos++;
            if (fd->pos >= offsetof(ClientTNSMsg, data))
            {
                switch (fd->message)
                {
                case TNS_TYPE_CONNECT:
                    fd->state = TNS_STATE_MESSAGE_CONNECT;
                    break;
                case TNS_TYPE_ACK:
                case TNS_TYPE_REFUSE:
                case TNS_TYPE_DATA:
                case TNS_TYPE_NULL:
                case TNS_TYPE_ABORT:
                case TNS_TYPE_RESEND:
                case TNS_TYPE_MARKER:
                case TNS_TYPE_ATTENTION:
                case TNS_TYPE_CONTROL:
                    if (fd->pos >= fd->stringlen)
                    {
                        if (offset == (args.size - 1))
                            goto done;
                        return reset_flow_data(fd);
                    }
                    fd->state = TNS_STATE_MESSAGE_DATA;
                    break;
                case TNS_TYPE_ACCEPT:
                case TNS_TYPE_REDIRECT:
                default:
                    return reset_flow_data(fd);
                }
            }
            break;
        case TNS_STATE_MESSAGE_CONNECT:
            fd->l.raw_len[fd->pos - CONNECT_VERSION_OFFSET] = args.data[offset];
            fd->pos++;
            if (fd->pos >= (CONNECT_VERSION_OFFSET + 2))
            {
                {
                    switch (ntohs(fd->l.len))
                    {
                    case 0x136:
                        fd->version = "8";
                        break;
                    case 0x137:
                        fd->version = "9i R1";
                        break;
                    case 0x138:
                        fd->version = "9i R2";
                        break;
                    case 0x139:
                        fd->version = "10g R1/R2";
                        break;
                    case 0x13A:
                        fd->version = "11g R1";
                        break;
                    default:
                        break;
                    }
                }
                fd->l.len = 0;
                fd->state = TNS_STATE_MESSAGE_CONNECT_OFFSET_DC;
            }
            break;
        case TNS_STATE_MESSAGE_CONNECT_OFFSET_DC:
            fd->pos++;
            if (fd->pos >= CONNECT_DATA_OFFSET)
                fd->state = TNS_STATE_MESSAGE_CONNECT_OFFSET;
            break;
        case TNS_STATE_MESSAGE_CONNECT_OFFSET:
            fd->l.raw_len[fd->pos - CONNECT_DATA_OFFSET] = args.data[offset];
            fd->pos++;
            if (fd->pos >= (CONNECT_DATA_OFFSET + 2))
            {
                fd->offsetlen = ntohs(fd->l.len);
                if (fd->offsetlen > args.size)
                {
                    return reset_flow_data(fd);
                }
                fd->state = TNS_STATE_MESSAGE_CONNECT_PREDATA;
            }
            break;
        case TNS_STATE_MESSAGE_CONNECT_PREDATA:
            fd->pos++;
            if (fd->pos >= fd->offsetlen)
            {
                fd->state = TNS_STATE_MESSAGE_CONNECT_DATA;
            }
            break;
        case TNS_STATE_MESSAGE_CONNECT_DATA:
            if (tolower(args.data[offset]) != USER_STRING[user_pos])
            {
                user_pos = 0;
                if (tolower(args.data[offset]) == USER_STRING[user_pos])
                    user_pos++;
            }
            else if (++user_pos > MAX_USER_POS)
            {
                user_start = offset+1;
                fd->state = TNS_STATE_COLLECT_USER;
            }

            fd->pos++;
            if (fd->pos  >= fd->stringlen)
            {
                if (offset == (args.size - 1))
                    goto done;
                return reset_flow_data(fd);
            }
            break;
        case TNS_STATE_COLLECT_USER:
            if (user_end == 0 && args.data[offset] == ')')
            {
                user_end = offset;
            }

            fd->pos++;
            if (fd->pos  >= fd->stringlen)
            {
                if (offset == (args.size - 1))
                    goto done;
                return reset_flow_data(fd);
            }
            break;
        case TNS_STATE_MESSAGE_DATA:
            fd->pos++;
            if (fd->pos >= fd->stringlen)
            {
                if (offset == (args.size - 1))
                    goto done;
                return reset_flow_data(fd);
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
    add_app(args.asd, APP_ID_ORACLE_TNS, APP_ID_ORACLE_DATABASE, fd->version);
    if (user_start && user_end && ((user_size = user_end - user_start) > 0))
    {
        /* we truncate extra long usernames */
        if (user_size > TNS_MAX_INFO_SIZE)
            user_size = TNS_MAX_INFO_SIZE;
        memcpy(username, &args.data[user_start], user_size);
        username[user_size] = 0;
        add_user(args.asd, username, APP_ID_ORACLE_DATABASE, true);
    }
    return APPID_SUCCESS;
}

