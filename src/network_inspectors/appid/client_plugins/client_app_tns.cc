//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

enum TNSClntState
{
    CLNT_MSG_LEN = 0,
    CLNT_MSG_CHECKSUM,
    CLNT_MSG,
    CLNT_MSG_RES,
    CLNT_MSG_HD_CHECKSUM,
    CLNT_MSG_DATA,
    CLNT_MSG_CONNECT,
    CLNT_MSG_CONNECT_OFFSET_DC,
    CLNT_MSG_CONNECT_OFFSET,
    CLNT_MSG_CONNECT_PREDATA,
    CLNT_MSG_CONNECT_DATA,
    CLNT_COLLECT_USER
};

class ClientTNSData : public AppIdFlowData
{
public:
    ~ClientTNSData() override = default;

    const char* version = nullptr;
    TNSClntState state = CLNT_MSG_LEN;
    unsigned stringlen = 0;
    unsigned offsetlen = 0;
    unsigned pos = 0;
    unsigned message = 0;
    union
    {
        uint16_t len;
        uint8_t raw_len[2];
    } l = {};
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


static int reset_flow_data(ClientTNSData& fd)
{
    fd = {};
    return APPID_EINVALID;
}

#define TNS_MAX_INFO_SIZE    63
int TnsClientDetector::validate(AppIdDiscoveryArgs& args)
{
    if (args.dir != APP_ID_FROM_INITIATOR)
        return APPID_INPROCESS;

    ClientTNSData* fd = (ClientTNSData*)data_get(args.asd);
    if (!fd)
    {
        fd = new ClientTNSData;
        data_add(args.asd, fd);
    }

    char username[TNS_MAX_INFO_SIZE + 1];
    int user_pos = 0;
    int user_size = 0;
    uint16_t user_start = 0;
    uint16_t user_end = 0;

    uint16_t offset = 0;
    while (offset < args.size)
    {
        // For some reason, coverity cannot follow the state machine. It does state transitions that are not possible
        // This makes the coverity overrun exceptions necessary
        switch (fd->state)
        {
        case CLNT_MSG_LEN:
            // coverity[overrun]
            fd->l.raw_len[fd->pos++] = args.data[offset];
            if (fd->pos >= offsetof(ClientTNSMsg, checksum))
            {
                fd->stringlen = ntohs(fd->l.len);
                if (fd->stringlen == 2)
                {
                    if (offset == args.size - 1)
                        goto done;
                    return reset_flow_data(*fd);
                }
                else if (fd->stringlen < 2)
                    return reset_flow_data(*fd);
                else if (fd->stringlen > args.size)
                    return reset_flow_data(*fd);
                fd->state = CLNT_MSG_CHECKSUM;
            }
            break;

        case CLNT_MSG_CHECKSUM:
            if (args.data[offset] != 0)
                return reset_flow_data(*fd);
            fd->pos++;
            if (fd->pos >= offsetof(ClientTNSMsg, msg))
                fd->state = CLNT_MSG;
            break;

        case CLNT_MSG:
            fd->message = args.data[offset];
            if (fd->message < TNS_TYPE_CONNECT || fd->message > TNS_TYPE_MAX)
                return reset_flow_data(*fd);
            fd->pos++;
            fd->state = CLNT_MSG_RES;
            break;
        case CLNT_MSG_RES:
            fd->state = CLNT_MSG_HD_CHECKSUM;
            fd->pos++;
            break;
        case CLNT_MSG_HD_CHECKSUM:
            fd->pos++;
            if (fd->pos >= offsetof(ClientTNSMsg, data))
            {
                switch (fd->message)
                {
                case TNS_TYPE_CONNECT:
                    fd->state = CLNT_MSG_CONNECT;
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
                        return reset_flow_data(*fd);
                    }
                    fd->state = CLNT_MSG_DATA;
                    break;
                case TNS_TYPE_ACCEPT:
                case TNS_TYPE_REDIRECT:
                default:
                    return reset_flow_data(*fd);
                }
            }
            break;
        case CLNT_MSG_CONNECT:
            // coverity[overrun]
            fd->l.raw_len[fd->pos - CONNECT_VERSION_OFFSET] = args.data[offset];
            fd->pos++;
            if (fd->pos == (CONNECT_VERSION_OFFSET + 2))
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
                fd->l.len = 0;
                fd->state = CLNT_MSG_CONNECT_OFFSET_DC;
            }
            break;
        case CLNT_MSG_CONNECT_OFFSET_DC:
            fd->pos++;
            if (fd->pos >= CONNECT_DATA_OFFSET)
                fd->state = CLNT_MSG_CONNECT_OFFSET;
            break;
        case CLNT_MSG_CONNECT_OFFSET:
            if (fd->pos >= CONNECT_DATA_OFFSET + 2)
                break;
            // coverity[overrun]
            fd->l.raw_len[fd->pos - CONNECT_DATA_OFFSET] = args.data[offset];
            fd->pos++;
            if (fd->pos == (CONNECT_DATA_OFFSET + 2))
            {
                fd->offsetlen = ntohs(fd->l.len);
                if (fd->offsetlen > args.size)
                    return reset_flow_data(*fd);
                fd->state = CLNT_MSG_CONNECT_PREDATA;
            }
            break;
        case CLNT_MSG_CONNECT_PREDATA:
            fd->pos++;
            if (fd->pos >= fd->offsetlen)
                fd->state = CLNT_MSG_CONNECT_DATA;
            break;
        case CLNT_MSG_CONNECT_DATA:
            if (tolower(args.data[offset]) != USER_STRING[user_pos])
            {
                user_pos = 0;
                if (tolower(args.data[offset]) == USER_STRING[user_pos])
                    user_pos++;
            }
            else if (++user_pos > MAX_USER_POS)
            {
                user_start = offset+1;
                fd->state = CLNT_COLLECT_USER;
            }

            fd->pos++;
            if (fd->pos  >= fd->stringlen)
            {
                if (offset == (args.size - 1))
                    goto done;
                return reset_flow_data(*fd);
            }
            break;
        case CLNT_COLLECT_USER:
            if (user_end == 0 && args.data[offset] == ')')
                user_end = offset;

            fd->pos++;
            if (fd->pos >= fd->stringlen)
            {
                if (offset == (args.size - 1))
                    goto done;
                return reset_flow_data(*fd);
            }
            break;
        case CLNT_MSG_DATA:
            fd->pos++;
            if (fd->pos >= fd->stringlen)
            {
                if (offset == (args.size - 1))
                    goto done;
                return reset_flow_data(*fd);
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
    add_app(args.asd, APP_ID_ORACLE_TNS, APP_ID_ORACLE_DATABASE, fd->version, args.change_bits);
    if (user_start && user_end && ((user_size = user_end - user_start) > 0))
    {
        /* we truncate extra long usernames */
        if (user_size > TNS_MAX_INFO_SIZE)
            user_size = TNS_MAX_INFO_SIZE;
        memcpy(username, &args.data[user_start], user_size);
        username[user_size] = 0;
        add_user(args.asd, username, APP_ID_ORACLE_DATABASE, true, args.change_bits);
    }
    return APPID_SUCCESS;
}
