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

// client_app_ssh.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_app_ssh.h"

#include "app_info_table.h"
#include "application_ids.h"

static const char SSH_CLIENT_BANNER[] = "SSH-";
#define SSH_CLIENT_BANNER_LEN (sizeof(SSH_CLIENT_BANNER)-1)
#define SSH_CLIENT_BANNER_MAXPOS (sizeof(SSH_CLIENT_BANNER)-2)

static const char DROPBEAR_BANNER[] = "dropbear";
#define DROPBEAR_BANNER_MAXPOS (sizeof(DROPBEAR_BANNER)-2)

static const char LSH_BANNER[] = "lsh";
#define LSH_BANNER_MAXPOS (sizeof(LSH_BANNER)-2)

static const char OPENSSH_BANNER[] = "OpenSSH";
#define OPENSSH_BANNER_MAXPOS (sizeof(OPENSSH_BANNER)-2)

static const char PUTTY_BANNER[] = "PuTTY";
#define PUTTY_BANNER_MAXPOS (sizeof(PUTTY_BANNER)-2)

#define SSH_MSG_KEYXINIT            20
#define SSH_MSG_IGNORE              2
#define SSH_MSG_SESSION_KEY         3
#define SSH_MAX_BANNER_LEN          255
#define SSH2                        2
#define SSH1                        1

enum SSHClientState
{
    SSH_CLIENT_STATE_BANNER = 0,
    SSH_CLIENT_STATE_ID_PROTO_VERSION,
    SSH_CLIENT_STATE_LOOKING_FOR_DASH,
    SSH_CLIENT_STATE_ID_CLIENT,
    SSH_CLIENT_STATE_CHECK_OPENSSH,
    SSH_CLIENT_STATE_CHECK_PUTTY,
    SSH_CLIENT_STATE_CHECK_LSH,
    SSH_CLIENT_STATE_CHECK_DROPBEAR,
    SSH_CLIENT_STATE_ID_SOFTWARE_VERSION,
    SSH_CLIENT_STATE_ID_REST_OF_LINE,
    SSH_CLIENT_STATE_KEY
};

enum SSH2HeaderState
{
    SSH2_HEADER_BEGIN,
    SSH2_HEADER_PLEN,
    SSH2_HEADER_CODE,
    SSH2_IGNORE,
    SSH2_PADDING,
    SSH2_KEYX_HEADER_FINISH,
    SSH2_FIELD_LEN_BEGIN,
    SSH2_FIELD_DATA_BEGIN,
    SSH2_PAYLOAD_BEGIN
};

enum SSH1HeaderState
{
    SSH1_HEADER_BEGIN,
    SSH1_HEADER_PLEN,
    SSH1_HEADER_FIND_CODE,
    SSH1_HEADER_CODE,
    SSH1_SESSION_KEY
};

struct ClientSSHData
{
    SSHClientState state;
    SSH2HeaderState hstate;
    SSH1HeaderState oldhstate;
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
    unsigned ssh_version;
    uint8_t version[SSH_MAX_BANNER_LEN];
    uint8_t plen;
    uint8_t code;
    uint32_t client_id;
};

#pragma pack(1)

struct ClientSSHKeyString
{
    uint32_t len;
    uint8_t data;
};

struct ClientSSHMsg
{
    uint32_t len;
    uint8_t plen;
    uint8_t code;
};

struct ClientSSH2KeyExchange
{
    ClientSSHMsg msg;
    uint8_t cookie[16];
};

struct ClientSSH1KeyExchangeV1
{
    uint32_t len;
    uint8_t code;
};

struct ClientSSHKeyExchangeFinal
{
    uint8_t kex_pkt;
    uint32_t future;
};

#pragma pack()

SshClientDetector::SshClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "SSH";
    proto = IpProtocol::TCP;
    minimum_matches = 1;
    provides_user = true;

    tcp_patterns =
    {
        { (const uint8_t*)SSH_CLIENT_BANNER, sizeof(SSH_CLIENT_BANNER) - 1,  0, 0, APP_ID_SSH },
        { (const uint8_t*)OPENSSH_BANNER,    sizeof(OPENSSH_BANNER) - 1,    -1, 0,
          APP_ID_OPENSSH },
        { (const uint8_t*)PUTTY_BANNER,      sizeof(PUTTY_BANNER) - 1,      -1, 0, APP_ID_PUTTY },
        { (const uint8_t*)LSH_BANNER,        sizeof(LSH_BANNER) - 1,         0, 0, APP_ID_LSH },
        { (const uint8_t*)DROPBEAR_BANNER,   sizeof(DROPBEAR_BANNER) - 1,   -1, 0,
          APP_ID_DROPBEAR },
    };

    appid_registry =
    {
        { APP_ID_DROPBEAR, APPINFO_FLAG_CLIENT_ADDITIONAL },
        { APP_ID_SSH, APPINFO_FLAG_CLIENT_ADDITIONAL },
        { APP_ID_LSH, APPINFO_FLAG_CLIENT_ADDITIONAL },
        { APP_ID_PUTTY, APPINFO_FLAG_CLIENT_ADDITIONAL },
        { APP_ID_OPENSSH, APPINFO_FLAG_CLIENT_ADDITIONAL }
    };

    handler->register_detector(name, this, proto);
}


static inline int ssh_client_validate_keyx(uint16_t offset, const uint8_t* data,
    uint16_t size, ClientSSHData* fd)
{
    const ClientSSHMsg* ckx;
    const ClientSSHKeyString* cks;
    const ClientSSH2KeyExchange* ckex;

    while (offset < size)
    {
        switch (fd->hstate)
        {
        case SSH2_HEADER_BEGIN:
            fd->l.raw_len[fd->pos] = data[offset];
            fd->pos++;
            if (fd->pos == sizeof(ckx->len))
            {
                fd->len = ntohl(fd->l.len);
                fd->hstate = SSH2_HEADER_PLEN;
            }
            break;
        case SSH2_HEADER_PLEN:
            fd->plen = data[offset];
            fd->hstate = SSH2_HEADER_CODE;
            fd->pos++;
            break;
        case SSH2_HEADER_CODE:
            fd->code = data[offset];
            if (fd->code == SSH_MSG_KEYXINIT)
            {
                fd->pos = 0;
                fd->hstate = SSH2_KEYX_HEADER_FINISH;
                fd->read_data = fd->plen + sizeof(ckex->cookie) + sizeof(ckx->len);
            }
            else if (fd->code == SSH_MSG_IGNORE)
            {
                fd->pos = sizeof(ckx->len) + 2;
                fd->hstate = SSH2_IGNORE;
            }
            else
                return APPID_EINVALID;
            fd->len = ntohl(fd->l.len) + sizeof(ckx->len);
            if (fd->len > 35000)
                return APPID_EINVALID;
            break;
        case SSH2_IGNORE:
            fd->pos++;
            if (fd->pos >= fd->len)
            {
                fd->hstate = SSH2_HEADER_BEGIN;
                fd->pos = 0;
            }
            break;
        case SSH2_KEYX_HEADER_FINISH:
            fd->pos++;
            if (fd->pos >= sizeof(ckex->cookie))
            {
                fd->hstate = SSH2_FIELD_LEN_BEGIN;
                fd->pos = 0;
            }
            break;
        case SSH2_FIELD_LEN_BEGIN:
            fd->l.raw_len[fd->pos] = data[offset];
            fd->pos++;
            if (fd->pos >= sizeof(cks->len))
            {
                fd->pos = 0;
                fd->field_len = ntohl(fd->l.len);
                fd->read_data += fd->field_len + sizeof(cks->len);
                if (fd->read_data > fd->len)
                    return APPID_EINVALID;
                if (fd->field_len)
                    fd->hstate = SSH2_FIELD_DATA_BEGIN;
                else
                {
                    fd->field++;
                    if (fd->field >= 10)
                        fd->hstate = SSH2_PAYLOAD_BEGIN;
                }
            }
            break;
        case SSH2_FIELD_DATA_BEGIN:
            fd->pos++;
            if (fd->pos >= fd->field_len)
            {
                fd->field++;
                if (fd->field >= 10)
                    fd->hstate = SSH2_PAYLOAD_BEGIN;
                else
                    fd->hstate = SSH2_FIELD_LEN_BEGIN;
                fd->pos = 0;
            }
            break;
        case SSH2_PAYLOAD_BEGIN:
            if (fd->pos >= offsetof(ClientSSHKeyExchangeFinal, future))
            {
                fd->l.raw_len[fd->pos - offsetof(ClientSSHKeyExchangeFinal, future)] =
                    data[offset];
            }
            fd->pos++;
            if (fd->pos >= sizeof(ClientSSHKeyExchangeFinal))
            {
                if (fd->l.len != 0)
                    return APPID_EINVALID;
                fd->hstate = SSH2_PADDING;
                fd->pos = 0;
            }
            break;
        case SSH2_PADDING:
            fd->pos++;
            if (fd->pos >= fd->plen)
            {
                offset++;
                // FIXIT-L if offset > size then there is probably a D-H Key Exchange Init packet
                // in this payload
                // For now parsing the Key Exchange Init is good enough to declare valid key
                // exchange but for
                // future enhance parsing to validate the D-H Key Exchange Init.
                if (offset == size)
                    return APPID_SUCCESS;
                else
                    return APPID_SUCCESS;
            }
            break;

        default:
            assert(0);  //  All cases should be handled above.
        }
        offset++;
    }
    return APPID_INPROCESS;
}

static inline int ssh_client_validate_pubkey(uint16_t offset, const uint8_t* data,
    uint16_t size, ClientSSHData* fd)
{
    const ClientSSHMsg* ckx;

    while (offset < size)
    {
        switch (fd->oldhstate)
        {
        case SSH1_HEADER_BEGIN:
            fd->l.raw_len[fd->pos] = data[offset];
            fd->pos++;
            if (fd->pos == sizeof(ckx->len))
            {
                fd->len = ntohl(fd->l.len);
                fd->oldhstate = SSH1_HEADER_PLEN;
            }
            break;
        case SSH1_HEADER_PLEN:
            if (size > (fd->len + sizeof(ckx->len)))
                fd->plen = size - (fd->len + sizeof(ckx->len));
            else
                fd->plen = 0;
            fd->oldhstate = SSH1_HEADER_FIND_CODE;
            // fallthrough
        case SSH1_HEADER_FIND_CODE:
            if (fd->pos == fd->plen + sizeof(ckx->len))
            {
                fd->oldhstate = SSH1_HEADER_CODE;
                fd->code = data[offset];
            }
            fd->pos++;
            break;
        case SSH1_HEADER_CODE:
            if (fd->code == SSH_MSG_SESSION_KEY)
            {
                fd->oldhstate = SSH1_SESSION_KEY;
                fd->pos++;
            }
            else
                return APPID_EINVALID;
            fd->len = fd->len + fd->plen + sizeof(ckx->len);
            if (fd->len > 35000)
                return APPID_EINVALID;
            break;
        case SSH1_SESSION_KEY:
            fd->pos++;
            if (fd->pos >= fd->len)
            {
                offset++;
                if (offset == size)
                    return APPID_SUCCESS;
                return APPID_EINVALID;
            }
            break;
        }
        offset++;
    }
    return APPID_INPROCESS;
}

static inline int ssh_client_sm(const uint8_t* data, uint16_t size,
    ClientSSHData* fd)
{
    uint16_t offset = 0;

    while (offset < size)
    {
        uint8_t d = data[offset];
        switch (fd->state)
        {
        case SSH_CLIENT_STATE_BANNER:
            if (d != SSH_CLIENT_BANNER[fd->pos])
                return APPID_EINVALID;
            if (fd->pos >= SSH_CLIENT_BANNER_MAXPOS)
                fd->state = SSH_CLIENT_STATE_ID_PROTO_VERSION;
            else
                fd->pos++;
            break;

        case SSH_CLIENT_STATE_ID_PROTO_VERSION:
            if (d == '1')
                fd->ssh_version = SSH1;
            else if (d == '2')
                fd->ssh_version = SSH2;
            else
                return APPID_EINVALID;
            fd->state = SSH_CLIENT_STATE_LOOKING_FOR_DASH;
            break;

        case SSH_CLIENT_STATE_LOOKING_FOR_DASH:
            if (d == '-')
            {
                fd->state = SSH_CLIENT_STATE_ID_CLIENT;
                break;
            }
            break;

        case SSH_CLIENT_STATE_ID_CLIENT:
            switch (d)
            {
            case 'O':
                fd->state = SSH_CLIENT_STATE_CHECK_OPENSSH;
                break;
            case 'P':
                fd->state = SSH_CLIENT_STATE_CHECK_PUTTY;
                break;
            case 'l':
                fd->state = SSH_CLIENT_STATE_CHECK_LSH;
                break;
            case 'd':
                fd->state = SSH_CLIENT_STATE_CHECK_DROPBEAR;
                break;
            default:
                fd->state = SSH_CLIENT_STATE_ID_REST_OF_LINE;
                fd->client_id = APP_ID_SSH;
            }
            /*the next thing we want to see is the SECOND character... */
            fd->pos = 1;
            break;

        case SSH_CLIENT_STATE_CHECK_OPENSSH:
            if (d != OPENSSH_BANNER[fd->pos])
            {
                fd->client_id = APP_ID_SSH;
                fd->state = SSH_CLIENT_STATE_ID_REST_OF_LINE;
            }
            else if (fd->pos >= OPENSSH_BANNER_MAXPOS)
            {
                fd->client_id = APP_ID_OPENSSH;
                fd->state = SSH_CLIENT_STATE_ID_SOFTWARE_VERSION;
                fd->pos = 0;
            }
            else
                fd->pos++;
            break;

        case SSH_CLIENT_STATE_CHECK_PUTTY:
            if (d != PUTTY_BANNER[fd->pos])
            {
                fd->client_id = APP_ID_SSH;
                fd->state = SSH_CLIENT_STATE_ID_REST_OF_LINE;
            }
            else if (fd->pos >= PUTTY_BANNER_MAXPOS)
            {
                fd->client_id = APP_ID_PUTTY;
                fd->state = SSH_CLIENT_STATE_ID_SOFTWARE_VERSION;
                fd->pos = 0;
            }
            else
                fd->pos++;
            break;

        case SSH_CLIENT_STATE_CHECK_LSH:
            if (d != LSH_BANNER[fd->pos])
            {
                fd->client_id = APP_ID_SSH;
                fd->state = SSH_CLIENT_STATE_ID_REST_OF_LINE;
            }
            else if (fd->pos >= LSH_BANNER_MAXPOS)
            {
                fd->client_id = APP_ID_LSH;
                fd->state = SSH_CLIENT_STATE_ID_SOFTWARE_VERSION;
                fd->pos = 0;
            }
            else
                fd->pos++;
            break;

        case SSH_CLIENT_STATE_CHECK_DROPBEAR:
            if (d != DROPBEAR_BANNER[fd->pos])
            {
                fd->client_id = APP_ID_SSH;
                fd->state = SSH_CLIENT_STATE_ID_REST_OF_LINE;
            }
            else if (fd->pos >= DROPBEAR_BANNER_MAXPOS)
            {
                fd->client_id = APP_ID_DROPBEAR;
                fd->state = SSH_CLIENT_STATE_ID_SOFTWARE_VERSION;
                fd->pos = 0;
            }
            else
                fd->pos++;
            break;

        case SSH_CLIENT_STATE_ID_SOFTWARE_VERSION:
            if (d == '\n')
            {
                fd->version[fd->pos] = 0;
                fd->pos = 0;
                fd->state = SSH_CLIENT_STATE_KEY;
                break;
            }
            if (d == ' ')
            {
                fd->version[fd->pos] = 0;
                fd->state = SSH_CLIENT_STATE_ID_REST_OF_LINE;
                break;
            }
            if (fd->pos < SSH_MAX_BANNER_LEN - 1 && d != '\r' && d != '-' && d != '_')
            {
                fd->version[fd->pos++] = d;
            }
            break;

        case SSH_CLIENT_STATE_ID_REST_OF_LINE:
            if (d == '\n')
            {
                fd->pos = 0;
                fd->state = SSH_CLIENT_STATE_KEY;
                break;
            }
            break;

        case SSH_CLIENT_STATE_KEY:
            switch (fd->ssh_version)
            {
            case SSH2:
                return ssh_client_validate_keyx(offset, data, size, fd);
                break;
            case SSH1:
                return ssh_client_validate_pubkey(offset, data, size, fd);
                break;
            default:
                return APPID_EINVALID;
                break;
            }
            break;

        default:
            return APPID_EINVALID;
        }
        offset++;
    }
    return APPID_INPROCESS;
}

int SshClientDetector::validate(AppIdDiscoveryArgs& args)
{
    ClientSSHData* fd;
    int sm_ret;

    if (!args.size || args.dir != APP_ID_FROM_INITIATOR)
        return APPID_INPROCESS;

    fd = ( ClientSSHData*)data_get(args.asd);
    if (!fd)
    {
        fd = (ClientSSHData*)snort_calloc(sizeof(ClientSSHData));
        data_add(args.asd, fd, &snort_free);
        fd->state = SSH_CLIENT_STATE_BANNER;
        fd->hstate = SSH2_HEADER_BEGIN;
        fd->oldhstate = SSH1_HEADER_BEGIN;
    }

    sm_ret = ssh_client_sm(args.data, args.size, fd);
    if (sm_ret != APPID_SUCCESS)
        return sm_ret;

    add_app(args.asd, APP_ID_SSH, fd->client_id, (const char*)fd->version);
    return APPID_SUCCESS;
}

