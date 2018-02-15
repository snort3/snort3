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

// service_nntp.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_nntp.h"

#include "application_ids.h"

#define NNTP_PORT   119

#define NNTP_COUNT_THRESHOLD 4

enum NNTPState
{
    NNTP_STATE_CONNECTION,
    NNTP_STATE_TRANSFER,
    NNTP_STATE_DATA,
    NNTP_STATE_CONNECTION_ERROR
};

#define NNTP_CR_RECEIVED    0x0001
#define NNTP_MID_LINE       0x0002
#define NNTP_MID_TERM       0x0004

struct ServiceNNTPData
{
    NNTPState state;
    uint32_t flags;
    unsigned count;
};

#pragma pack(1)

struct ServiceNNTPCode
{
    uint8_t code[3];
    uint8_t sp;
};

#pragma pack()

#define NNTP_PATTERN1 "200 "
#define NNTP_PATTERN2 "201 "

NntpServiceDetector::NntpServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "nntp";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)NNTP_PATTERN1, sizeof(NNTP_PATTERN1) - 1, 0, 0, 0 },
        { (const uint8_t*)NNTP_PATTERN2, sizeof(NNTP_PATTERN2) - 1, 0, 0, 0 },
    };

    appid_registry =
    {
        { APP_ID_NNTP, 0 }
    };

    service_ports =
    {
        { NNTP_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


static int nntp_validate_reply(const uint8_t* data, uint16_t* offset, uint16_t size)
{
    const ServiceNNTPCode* code_hdr;
    int code;

    /* Trim any blank lines (be a little tolerant) */
    for (; *offset < size; (*offset)++)
    {
        if (data[*offset] != 0x0D && data[*offset] != 0x0A)
            break;
    }

    if (size - *offset < (int)sizeof(ServiceNNTPCode))
    {
        for (; *offset < size; (*offset)++)
        {
            if (!isspace(data[*offset]))
                return -1;
        }
        return 0;
    }

    code_hdr = (const ServiceNNTPCode*)(data + *offset);

    if (code_hdr->sp != ' ')
        return -1;

    if (code_hdr->code[0] < '1' || code_hdr->code[0] > '5')
        return -1;
    code = (code_hdr->code[0] - '0') * 100;

    if (code_hdr->code[1] < '0' ||
        (code_hdr->code[1] > '5' && code_hdr->code[1] < '8') ||
        code_hdr->code[1] > '9')
    {
        return -1;
    }
    code += (code_hdr->code[1] - '0') * 10;

    if (!isdigit(code_hdr->code[2]))
        return -1;
    code += code_hdr->code[2] - '0';

    /* We have a valid code, now we need to see if the rest of the line
        is okay */

    *offset += sizeof(ServiceNNTPCode);
    for (; *offset < size; (*offset)++)
    {
        if (data[*offset] == 0x0D)
        {
            (*offset)++;
            if (*offset >= size)
                return -1;
            if (data[*offset] != 0x0A)
                return -1;
        }
        if (data[*offset] == 0x0A)
        {
            (*offset)++;
            return code;
        }
        else if (!isprint(data[*offset]))
            return -1;
    }

    return 0;
}

static int nntp_validate_data(const uint8_t* data, uint16_t* offset, uint16_t size, int* flags)
{
    if (*flags & NNTP_CR_RECEIVED)
    {
        if (data[*offset] != 0x0A)
            return -1;
        if (*flags & NNTP_MID_TERM)
        {
            *flags = 0;
            (*offset)++;
            return 1;
        }
        *flags &= ~NNTP_CR_RECEIVED;
        (*offset)++;
    }
    if (*flags & NNTP_MID_TERM)
    {
        if (*offset >= size)
            return 0;
        if (data[*offset] == 0x0D)
        {
            *flags |= NNTP_CR_RECEIVED;
            (*offset)++;
            if (*offset >= size)
                return 0;
            if (data[*offset] != 0x0A)
                return -1;
            *flags = 0;
            (*offset)++;
            return 1;
        }
        else if (data[*offset] == 0x0A)
        {
            *flags = 0;
            (*offset)++;
            return 1;
        }
        else if (data[*offset] != '.')
            return -1;
        *flags = NNTP_MID_LINE;
        (*offset)++;
    }
    for (; *offset < size; (*offset)++)
    {
        if (!(*flags & NNTP_MID_LINE))
        {
            if (data[*offset] == '.')
            {
                *flags |= NNTP_MID_TERM;
                (*offset)++;
                if (*offset >= size)
                    return 0;
                if (data[*offset] == 0x0D)
                {
                    *flags |= NNTP_CR_RECEIVED;
                    (*offset)++;
                    if (*offset >= size)
                        return 0;
                    if (data[*offset] != 0x0A)
                        return -1;
                    *flags = 0;
                    (*offset)++;
                    return 1;
                }
                else if (data[*offset] == 0x0A)
                {
                    *flags = 0;
                    (*offset)++;
                    return 1;
                }
                else if (data[*offset] != '.')
                    return -1;
                (*offset)++;
            }
        }
        *flags = NNTP_MID_LINE;
        for (; *offset < size; (*offset)++)
        {
            if (data[*offset] == 0x0D)
            {
                (*offset)++;
                if (*offset >= size)
                {
                    *flags |= NNTP_CR_RECEIVED;
                    return 0;
                }
                if (data[*offset] != 0x0A)
                    return -1;
                *flags = 0;
                break;
            }
            if (data[*offset] == 0x0A)
            {
                *flags = 0;
                break;
            }
        }
    }
    return 0;
}

int NntpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceNNTPData* nd;
    uint16_t offset;
    int code;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    nd = (ServiceNNTPData*)data_get(args.asd);
    if (!nd)
    {
        nd = (ServiceNNTPData*)snort_calloc(sizeof(ServiceNNTPData));
        data_add(args.asd, nd, &snort_free);
        nd->state = NNTP_STATE_CONNECTION;
    }

    offset = 0;
    while (offset < size)
    {
        if (nd->state == NNTP_STATE_DATA)
        {
            if ((code=nntp_validate_data(data, &offset, size, (int*)&nd->flags)) < 0)
                goto fail;
            if (!code)
                goto inprocess;
            nd->state = NNTP_STATE_TRANSFER;
        }
        if ((code=nntp_validate_reply(data, &offset, size)) < 0)
            goto fail;
        if (!code)
            goto inprocess;
        if (code == 400 || code == 502)
        {
            nd->state = NNTP_STATE_CONNECTION_ERROR;
        }
        else
        {
            switch (nd->state)
            {
            case NNTP_STATE_CONNECTION:
                switch (code)
                {
                case 201:
                case 200:
                    nd->state = NNTP_STATE_TRANSFER;
                    break;
                default:
                    goto fail;
                }
                break;
            case NNTP_STATE_TRANSFER:
                nd->count++;
                if (nd->count >= NNTP_COUNT_THRESHOLD)
                    goto success;
                switch (code)
                {
                case 100:
                case 215:
                case 220:
                case 221:
                case 222:
                case 224:
                case 230:
                case 231:
                    nd->state = NNTP_STATE_DATA;
                    break;
                }
                break;
            case NNTP_STATE_CONNECTION_ERROR:
            default:
                goto fail;
            }
        }
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    return add_service(args.asd, args.pkt, args.dir, APP_ID_NNTP);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

