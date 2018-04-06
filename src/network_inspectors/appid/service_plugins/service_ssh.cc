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

// service_ssh.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_ssh.h"

#include "app_info_table.h"
#include "application_ids.h"

#define SSH_PORT    22

#define SSH_BANNER "SSH-"
#define SERVICE_SSH_MSG_KEYXINIT 20
#define SERVICE_SSH_MSG_IGNORE 2
#define SERVICE_SSH_MSG_PUBLIC_KEY 2
#define SERVICE_SSH_KEY_STRINGS 10
#define SSH_MAX_FIELDS 10
#define SSH_MAX_BANNER_LENGTH 255

#define SSH_VERSION_2    2
#define SSH_VERSION_1    1
#define MINIMUM_SSH_VERS_LEN    4

enum SSHState
{
    SSH_STATE_BANNER,
    SSH_STATE_KEY,
    SSH_STATE_DONE
};

enum SSHHeaderState
{
    SSH_HEADER_BEGIN,
    SSH_HEADER_PLEN,
    SSH_HEADER_CODE,
    SSH_IGNORE,
    SSH_PADDING,
    SSH_KEYX_HEADER_FINISH,
    SSH_FIELD_LEN_BEGIN,
    SSH_FIELD_DATA_BEGIN,
    SSH_PAYLOAD_BEGIN
};

enum OldSSHHeaderState
{
    OLD_SSH_HEADER_BEGIN,
    OLD_SSH_HEADER_PLEN,
    OLD_SSH_HEADER_FIND_CODE,
    OLD_SSH_HEADER_CODE,
    OLD_SSH_PUBLIC_KEY
};

struct ServiceSSHData
{
    SSHState state;
    SSHHeaderState hstate;
    OldSSHHeaderState oldhstate;
    unsigned len;
    unsigned pos;
    unsigned field;
    unsigned field_len;
    unsigned read_data;
    union
    {
        uint32_t len;
        uint8_t raw_len[4];
    } l;
    char* vendor;
    char* version;
    unsigned ssh_version;
    uint8_t plen;
    uint8_t code;
};

#pragma pack(1)

struct ServiceSSHKeyString
{
    uint32_t len;
    uint8_t data;
};

struct ServiceSSHMsg
{
    uint32_t len;
    uint8_t plen;
    uint8_t code;
};

struct ServiceSSHKeyExchange
{
    ServiceSSHMsg msg;
    uint8_t cookie[16];
};

struct ServiceSSHKeyExchangeV1
{
    uint32_t len;
    uint8_t code;
};

struct ServiceSSHKeyExchangeFinal
{
    uint8_t kex_pkt;
    uint32_t future;
};

#pragma pack()

SshServiceDetector::SshServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "ssh";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)SSH_BANNER, sizeof(SSH_BANNER) - 1, 0, 0, 0 },
    };

    appid_registry =
    {
        { APP_ID_SSH, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { SSH_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


static int ssh_validate_pubkey(const uint8_t* data, uint16_t size, ServiceSSHData* ss)
{
    uint16_t offset = 0;
    const ServiceSSHMsg* skx;

    while (offset < size)
    {
        switch (ss->oldhstate)
        {
        case OLD_SSH_HEADER_BEGIN:
            ss->l.raw_len[ss->pos] = data[offset];
            ss->pos++;
            if (ss->pos == sizeof(skx->len))
            {
                ss->len = ntohl(ss->l.len);
                ss->oldhstate = OLD_SSH_HEADER_PLEN;
            }
            break;
        case OLD_SSH_HEADER_PLEN:
            if (size > (ss->len + sizeof(skx->len)))
                ss->plen = size - (ss->len + sizeof(skx->len));
            else
                ss->plen = 0;
            ss->oldhstate = OLD_SSH_HEADER_FIND_CODE;
            // fallthrough
        case OLD_SSH_HEADER_FIND_CODE:
            if (ss->pos == ss->plen + sizeof(skx->len))
            {
                ss->oldhstate = OLD_SSH_HEADER_CODE;
                ss->code = data[offset];
            }
            ss->pos++;
            break;
        case OLD_SSH_HEADER_CODE:
            if (ss->code == SERVICE_SSH_MSG_PUBLIC_KEY)
            {
                ss->oldhstate = OLD_SSH_PUBLIC_KEY;
                ss->pos++;
            }
            else
                return APPID_NOMATCH;
            ss->len = ss->len + ss->plen + sizeof(skx->len);
            if (ss->len > 35000)
                return APPID_NOMATCH;
            break;
        case OLD_SSH_PUBLIC_KEY:
            ss->pos++;
            if (ss->pos >= ss->len)
            {
                offset++;
                if (offset == size)
                    return APPID_SUCCESS;
                return APPID_NOMATCH;
            }
            break;
        }
        offset++;
    }
    return APPID_INPROCESS;
}

static int ssh_validate_keyx(const uint8_t* data, uint16_t size, ServiceSSHData* ss)
{
    uint16_t offset = 0;
    const ServiceSSHMsg* skx;
    const ServiceSSHKeyString* sks;
    const ServiceSSHKeyExchange* skex;

    while (offset < size)
    {
        switch (ss->hstate)
        {
        case SSH_HEADER_BEGIN:
            ss->l.raw_len[ss->pos] = data[offset];
            ss->pos++;
            if (ss->pos == sizeof(skx->len))
            {
                ss->len = ntohl(ss->l.len);
                ss->hstate = SSH_HEADER_PLEN;
            }
            break;
        case SSH_HEADER_PLEN:
            ss->plen = data[offset];
            ss->hstate = SSH_HEADER_CODE;
            ss->pos++;
            break;
        case SSH_HEADER_CODE:
            ss->code = data[offset];
            if (ss->code == SERVICE_SSH_MSG_KEYXINIT)
            {
                ss->pos = 0;
                ss->hstate = SSH_KEYX_HEADER_FINISH;
                ss->read_data = ss->plen + sizeof(skex->cookie) + sizeof(skx->len);
            }
            else if (ss->code == SERVICE_SSH_MSG_IGNORE)
            {
                ss->pos = sizeof(skx->len) + 2;
                ss->hstate = SSH_IGNORE;
            }
            else
                return APPID_NOMATCH;
            ss->len = ntohl(ss->l.len) + sizeof(skx->len);
            if (ss->len > 35000)
                return APPID_NOMATCH;
            break;
        case SSH_IGNORE:
            ss->pos++;
            if (ss->pos >= ss->len)
            {
                ss->hstate = SSH_HEADER_BEGIN;
                ss->pos = 0;
            }
            break;
        case SSH_KEYX_HEADER_FINISH:
            ss->pos++;
            if (ss->pos >= sizeof(skex->cookie))
            {
                ss->hstate = SSH_FIELD_LEN_BEGIN;
                ss->pos = 0;
            }
            break;
        case SSH_FIELD_LEN_BEGIN:
            ss->l.raw_len[ss->pos] = data[offset];
            ss->pos++;
            if (ss->pos >= sizeof(sks->len))
            {
                ss->pos = 0;
                ss->field_len = ntohl(ss->l.len);
                ss->read_data += ss->field_len + sizeof(sks->len);
                if (ss->read_data > ss->len)
                    return APPID_NOMATCH;
                if (ss->field_len)
                    ss->hstate = SSH_FIELD_DATA_BEGIN;
                else
                {
                    ss->field++;
                    if (ss->field >= 10)
                        ss->hstate = SSH_PAYLOAD_BEGIN;
                }
            }
            break;
        case SSH_FIELD_DATA_BEGIN:
            ss->pos++;
            if (ss->pos >= ss->field_len)
            {
                ss->field++;
                if (ss->field >= 10)
                    ss->hstate = SSH_PAYLOAD_BEGIN;
                else
                    ss->hstate = SSH_FIELD_LEN_BEGIN;
                ss->pos = 0;
            }
            break;
        case SSH_PAYLOAD_BEGIN:
            if (ss->pos >= offsetof(ServiceSSHKeyExchangeFinal, future))
            {
                ss->l.raw_len[ss->pos - offsetof(ServiceSSHKeyExchangeFinal, future)] =
                    data[offset];
            }
            ss->pos++;
            if (ss->pos >= sizeof(ServiceSSHKeyExchangeFinal))
            {
                if (ss->l.len != 0)
                    return APPID_NOMATCH;
                ss->hstate = SSH_PADDING;
                ss->pos = 0;
            }
            break;
        case SSH_PADDING:
            ss->pos++;
            if (ss->pos >= ss->plen)
            {
                offset++;
                if (offset == size)
                    return APPID_SUCCESS;
                return APPID_NOMATCH;
            }
            break;
        }
        offset++;
    }
    return APPID_INPROCESS;
}

static void ssh_free_state(void* data)
{
    ServiceSSHData* sd = (ServiceSSHData*)data;

    if (sd)
    {
        if (sd->vendor)
        {
            snort_free(sd->vendor);
            sd->vendor = nullptr;
        }
        if (sd->version)
        {
            snort_free(sd->version);
            sd->version = nullptr;
        }
        snort_free(sd);
    }
}

int SshServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceSSHData* ss;
    uint16_t offset;
    int retval;
    const char* ven;
    const char* ver;
    const char* end;
    unsigned len;
    int client_major;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;

    ss = (ServiceSSHData*)data_get(args.asd);
    if (!ss)
    {
        ss = (ServiceSSHData*)snort_calloc(sizeof(ServiceSSHData));
        data_add(args.asd, ss, &ssh_free_state);
        ss->state = SSH_STATE_BANNER;
        ss->hstate = SSH_HEADER_BEGIN;
        ss->oldhstate = OLD_SSH_HEADER_BEGIN;
    }

    if (args.dir != APP_ID_FROM_RESPONDER)
    {
        if (!ss->ssh_version)
        {
            if ((size_t)size > (sizeof(SSH_BANNER)-1+MINIMUM_SSH_VERS_LEN) &&
                !strncmp(SSH_BANNER, (const char*)data, sizeof(SSH_BANNER)-1))
            {
                data += (sizeof(SSH_BANNER)-1);
                if (!isdigit(*data))
                    goto not_compatible;
                else
                    client_major = *data;
                data++;
                if (*data != '.')
                    goto not_compatible;
                switch (client_major)
                {
                case 0x31:
                    if (*(data+1) == 0x39 && *(data+2) == 0x39)
                        ss->ssh_version = SSH_VERSION_2;
                    else
                        ss->ssh_version = SSH_VERSION_1;
                    break;
                case 0x32:
                    ss->ssh_version = SSH_VERSION_2;
                    break;
                default:
                    goto not_compatible;
                }
            }
        }
        goto inprocess;
    }

    switch (ss->state)
    {
    case SSH_STATE_BANNER:
        offset = 0;
        ss->state = SSH_STATE_KEY;
        for (;; )
        {
            /* SSH-v-\n where v is at least 1 character */
            if ((size_t)(size-offset) < ((sizeof(SSH_BANNER)-1)+3))
            {
                goto fail;
            }
            if (!strncmp(SSH_BANNER, (const char*)data+offset, sizeof(SSH_BANNER)-1))
            {
                unsigned blen = sizeof(SSH_BANNER)-1;
                offset += sizeof(SSH_BANNER)-1;
                for (;
                    offset<size && blen<=SSH_MAX_BANNER_LENGTH;
                    offset++, blen++)
                {
                    if (data[offset] == '-')
                        break;
                    if (!isprint(data[offset]) || isspace(data[offset]))
                    {
                        goto fail;
                    }
                }
                offset++;
                blen++;
                if (offset >= size || blen > SSH_MAX_BANNER_LENGTH)
                {
                    goto fail;
                }
                ven = (const char*)&data[offset];
                for (;
                    offset<size && blen<=SSH_MAX_BANNER_LENGTH;
                    offset++, blen++)
                {
                    if (data[offset] == 0x0D || data[offset] == 0x0A)
                    {
                        if (data[offset] == 0x0D)
                        {
                            if (offset+1 >= size)
                                goto fail;
                            if (data[offset+1] != 0x0A)
                                goto fail;
                        }
                        end = (const char*)&data[offset];
                        if (ven == end)
                            goto inprocess;
                        for (ver=ven; ver < end && *ver && *ver != '_' && *ver != '-'; ver++)
                            ;
                        if (ver < (end - 1) && isdigit(*(ver+1)))
                        {
                            len = ver - ven;
                            ss->vendor = (char*)snort_alloc(len+1);
                            memcpy(ss->vendor, ven, len);
                            ss->vendor[len] = 0;
                            ver++;
                            len = end - ver;
                            ss->version = (char*)snort_alloc(len+1);
                            memcpy(ss->version, ver, len);
                            ss->version[len] = 0;
                        }
                        else
                        {
                            len = end - ven;
                            ss->version = (char*)snort_calloc(len+1);
                            memcpy(ss->version, ven, len);
                            ss->version[len] = 0;
                        }
                        goto inprocess;
                    }
                    else if (!isprint(data[offset]))
                        goto fail;
                }
                goto fail;
            }
            else
            {
                for (; offset<size; offset++)
                {
                    if (data[offset] == 0x0a)
                    {
                        offset++;
                        break;
                    }
                }
            }
        }
        break;
    case SSH_STATE_KEY:
        switch (ss->ssh_version)
        {
        case SSH_VERSION_2:
            retval = ssh_validate_keyx(data, size, ss);
            break;
        case SSH_VERSION_1:
            retval = ssh_validate_pubkey(data, size, ss);
            break;
        default:
            goto fail;
        }
        goto done;
    default:
        break;
    }
    goto fail;

done:
    switch (retval)
    {
    case APPID_INPROCESS:
inprocess:
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;

    case APPID_SUCCESS:
        return add_service(args.asd, args.pkt, args.dir, APP_ID_SSH, ss->vendor, ss->version, nullptr);

    case APPID_NOMATCH:
fail:
        fail_service(args.asd, args.pkt, args.dir);
        return APPID_NOMATCH;

not_compatible:
        incompatible_data(args.asd, args.pkt, args.dir);
        return APPID_NOT_COMPATIBLE;

    default:
        return retval;
    }
}

