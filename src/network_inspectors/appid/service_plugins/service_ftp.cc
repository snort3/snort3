//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// service_ftp.cc author Sourcefire Inc.

#include "service_ftp.h"

#include "main/snort_debug.h"
#include "sfip/sf_ip.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "appid_api.h"
#include "appid_flow_data.h"
#include "application_ids.h"
#include "service_base.h"
#include "service_util.h"
#include "appid_module.h"

// FIXIT-H This needs to use a real SFIP function
static SFIP_RET sfip_convert_ip_text_to_binary(const int, const char*, void*)
{ return SFIP_SUCCESS; }

#define FTP_PORT    21
/*#define RNA_FTP_EXPECTED_ON_PORT    1 */

enum FTPState
{
    FTP_STATE_CONNECTION,
    FTP_STATE_LOGIN,
    FTP_STATE_PASSWORD,
    FTP_STATE_ACCOUNT,
    FTP_STATE_CONNECTION_ERROR,
    FTP_STATE_MONITOR
};

enum FTPReplyState
{
    FTP_REPLY_BEGIN,
    FTP_REPLY_MULTI,
    FTP_REPLY_MID
};

enum FTPCmd
{
    FTP_CMD_NONE,
    FTP_CMD_PORT_EPRT,
    FTP_CMD_PASV_EPSV
};

#define MAX_STRING_SIZE 64
struct ServiceFTPData
{
    FTPState state;
    FTPReplyState rstate;
    int code;
    char vendor[MAX_STRING_SIZE];
    char version[MAX_STRING_SIZE];
    FTPCmd cmd;
    sfip_t address;
    uint16_t port;
};

#pragma pack(1)

struct ServiceFTPCode
{
    uint8_t code[3];
    uint8_t sp;
};

#pragma pack()

static int ftp_init(const IniServiceAPI* const init_api);
static int ftp_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &ftp_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "ftp"
};

static RNAServiceValidationPort pp[] =
{
    { &ftp_validate, FTP_PORT, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule ftp_service_mod =
{
    "FTP",
    &ftp_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

#define FTP_PATTERN1 "220 "
#define FTP_PATTERN2 "220-"
#define FTP_PATTERN3 "FTP"
#define FTP_PATTERN4 "ftp"

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_FTP_CONTROL, APPINFO_FLAG_SERVICE_ADDITIONAL },
    { APP_ID_FTP_ACTIVE,  APPINFO_FLAG_SERVICE_ADDITIONAL },
    { APP_ID_FTP_PASSIVE, APPINFO_FLAG_SERVICE_ADDITIONAL },
    { APP_ID_FTPS,        APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static int16_t ftp_data_app_id = 0;

static int ftp_init(const IniServiceAPI* const init_api)
{
    ftp_data_app_id = AddProtocolReference("ftp-data");

    init_api->RegisterPattern(&ftp_validate, IpProtocol::TCP, (uint8_t*)FTP_PATTERN1,
        sizeof(FTP_PATTERN1)-1, 0, "ftp", init_api->pAppidConfig);
    init_api->RegisterPattern(&ftp_validate, IpProtocol::TCP, (uint8_t*)FTP_PATTERN2,
        sizeof(FTP_PATTERN2)-1, 0, "ftp", init_api->pAppidConfig);
    init_api->RegisterPattern(&ftp_validate, IpProtocol::TCP, (uint8_t*)FTP_PATTERN3,
        sizeof(FTP_PATTERN3)-1, -1, "ftp", init_api->pAppidConfig);
    init_api->RegisterPattern(&ftp_validate, IpProtocol::TCP, (uint8_t*)FTP_PATTERN4,
        sizeof(FTP_PATTERN4)-1, -1, "ftp", init_api->pAppidConfig);
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&ftp_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static inline void CopyVendorString(ServiceFTPData* fd, const uint8_t* vendor, unsigned int
    vendorLen)
{
    unsigned int copyLen = vendorLen < sizeof(fd->vendor)-1 ? vendorLen : sizeof(fd->vendor)-1;
    memcpy(fd->vendor, vendor, copyLen);
    fd->vendor[copyLen] = '\0';
}

static inline void CopyVersionString(ServiceFTPData* fd, const uint8_t* version, unsigned int
    versionLen)
{
    unsigned int copyLen = versionLen < sizeof(fd->version)-1 ? versionLen : sizeof(fd->version)-1;
    while (copyLen > 0 && !isalnum(version[copyLen-1]))
    {
        copyLen--;
    }
    memcpy(fd->version, version, copyLen);
    fd->version[copyLen] = '\0';
}

enum VVP_PARSE_ENUM
{
    VVP_PARSE_HP = 1,
    VVP_PARSE_FILEZILLA = 2,
    VVP_PARSE_MS = 3,
    VVP_PARSE_WU = 4,
    VVP_PARSE_PRO_FTPD = 5,
    VVP_PARSE_PURE_FTPD = 6,
    VVP_PARSE_NC_FTPD = 7
};

static int VendorVersionParse(const uint8_t* data, uint16_t init_offset,
    uint16_t offset, ServiceFTPData* fd,
    const uint8_t* vendorCandidate, unsigned int vendorCandidateLen,
    const uint8_t* optionalVersion, unsigned int versionLen,
    VVP_PARSE_ENUM vvp_parse_type)
{
    const unsigned char* p;
    const unsigned char* end;
    const unsigned char* ver;
    unsigned int verlen;
    int ret = 0; // no match

    p = &data[init_offset];
    end = &data[offset-1];
    /* Search for the vendorCandidate string */
    if (vvp_parse_type == VVP_PARSE_WU)
    {
        /* Search for the version string */
        if ((p = service_strstr(p, end-p, optionalVersion, versionLen)))
        {
            /* If we like the version we will just assign the vendor */
            CopyVendorString(fd, vendorCandidate, vendorCandidateLen);
            ret = 1;

            /* Found the version string.  Move just past the version string */
            ver = p + versionLen;
            p = ver;
            verlen = 0;
            while (p < end && *p && *p != ' ' )
            {
                p++; verlen++;
            }
            CopyVersionString(fd, ver, verlen);
        }
    }
    else if ((p=service_strstr(p, end-p, vendorCandidate, vendorCandidateLen)))
    {
        /* Found vendorCandidate string */
        CopyVendorString(fd, vendorCandidate, vendorCandidateLen);
        ret = 1;
        /* Move just past the vendor string */
        p += vendorCandidateLen;
        if (optionalVersion)
        {
            /* Search for the version string */
            if ((p = service_strstr(p, end-p, optionalVersion, versionLen)))
            {
                /* Found the version string.  Move just past the version string */
                ver = p + versionLen;
                p = ver;
                verlen = 0;
                switch (vvp_parse_type)
                {
                case VVP_PARSE_HP:
                    while (p < end && *p && (isalnum(*p) || *p == '.'))
                    {
                        p++; verlen++;
                    }
                    break;
                case VVP_PARSE_FILEZILLA:
                    while (p < end && *p && (isalnum(*p) || *p == '.' || *p == ' '))
                    {
                        p++; verlen++;
                    }
                    break;
                case VVP_PARSE_MS:
                    while (p < end && *p && *p != ')' )
                    {
                        p++; verlen++;
                    }
                    break;
                case VVP_PARSE_PRO_FTPD:
                    while (p < end && *p && *p != ' ' )
                    {
                        p++; verlen++;
                    }
                    break;
                default:
                    break;
                }
                CopyVersionString(fd, ver, verlen);
            }
        }
    }
    return ret;
}

static int CheckVendorVersion(const uint8_t* data, uint16_t init_offset,
    uint16_t offset, ServiceFTPData* fd, VVP_PARSE_ENUM vvp_parse_type)
{
    static const unsigned char ven_hp[] = "Hewlett-Packard FTP Print Server";
    static const unsigned char ver_hp[] = "Version ";
    static const unsigned char ven_fzilla[] = "FileZilla Server";
    static const unsigned char ver_fzilla[] = "version ";
    static const unsigned char ven_ms[] = "Microsoft FTP Service";
    static const unsigned char ver_ms[] = "(Version ";
    static const unsigned char ven_wu[] = "wu";
    static const unsigned char ver_wu[] = "(Version wu-";
    static const unsigned char ven_proftpd[] = "ProFTPD";
    static const unsigned char ven_pureftpd[] = "Pure-FTPd";
    static const unsigned char ven_ncftpd[] = "NcFTPd";

    if (!data || init_offset >= offset)
        return 0;

    switch (vvp_parse_type)
    {
    case VVP_PARSE_HP:
        return VendorVersionParse(data, init_offset, offset,fd,
            ven_hp, sizeof(ven_hp)-1,
            ver_hp, sizeof(ver_hp)-1,
            VVP_PARSE_HP);
    case VVP_PARSE_FILEZILLA:
        return VendorVersionParse(data, init_offset, offset,fd,
            ven_fzilla, sizeof(ven_fzilla)-1,
            ver_fzilla, sizeof(ver_fzilla)-1,
            VVP_PARSE_FILEZILLA);
    case VVP_PARSE_MS:
        return VendorVersionParse(data, init_offset, offset,fd,
            ven_ms, sizeof(ven_ms)-1,
            ver_ms, sizeof(ver_ms)-1,
            VVP_PARSE_MS);
    case VVP_PARSE_WU:
        return VendorVersionParse(data, init_offset, offset,fd,
            ven_wu, sizeof(ven_wu)-1,
            ver_wu, sizeof(ver_wu)-1,
            VVP_PARSE_WU);
    case VVP_PARSE_PRO_FTPD:
        return VendorVersionParse(data, init_offset, offset,fd,
            ven_proftpd, sizeof(ven_proftpd)-1,
            (const uint8_t*)" ", sizeof(" ")-1,
            VVP_PARSE_PRO_FTPD);
    case VVP_PARSE_PURE_FTPD:
        return VendorVersionParse(data, init_offset, offset,fd,
            ven_pureftpd, sizeof(ven_pureftpd)-1,
            nullptr, 0,
            VVP_PARSE_PURE_FTPD);
    case VVP_PARSE_NC_FTPD:
        return VendorVersionParse(data, init_offset, offset,fd,
            ven_ncftpd, sizeof(ven_ncftpd)-1,
            nullptr, 0,
            VVP_PARSE_NC_FTPD);
    }
    return 0;
}

static int ftp_validate_reply(const uint8_t* data, uint16_t* offset,
    uint16_t size, ServiceFTPData* fd)
{
    const ServiceFTPCode* code_hdr;
    int tmp;
    FTPReplyState tmp_state;

    for (; *offset < size; (*offset)++)
    {
        /* Trim any blank lines (be a little tolerant) */
        for (; *offset<size; (*offset)++)
        {
            if (data[*offset] != 0x0D && data[*offset] != 0x0A)
                break;
        }

        switch (fd->rstate)
        {
        case FTP_REPLY_BEGIN:
            if (size - (*offset) < (int)sizeof(ServiceFTPCode))
                return -1;

            code_hdr = (ServiceFTPCode*)(data + *offset);

            if (code_hdr->sp == '-')
                fd->rstate = FTP_REPLY_MULTI;
            else if (code_hdr->sp != ' ' && code_hdr->sp != 0x09)
                return -1;

            if (code_hdr->code[0] < '1' || code_hdr->code[0] > '5')
                return -1;
            fd->code = (code_hdr->code[0] - '0') * 100;

            if (code_hdr->code[1] < '0' || code_hdr->code[1] > '5')
                return -1;
            fd->code += (code_hdr->code[1] - '0') * 10;

            if (!isdigit(code_hdr->code[2]))
                return -1;
            fd->code += code_hdr->code[2] - '0';

            *offset += sizeof(ServiceFTPCode);
            tmp_state = fd->rstate;

            if (!fd->vendor[0] && !fd->version[0])
            {
                if (fd->code == 220)
                {
                    // These vendor strings are present on the first "220" whether that is the
                    // "220-" or "220 "
                    if (!CheckVendorVersion(data, *offset, size, fd, VVP_PARSE_MS) &&
                        !CheckVendorVersion(data, *offset, size, fd, VVP_PARSE_WU) &&
                        !CheckVendorVersion(data, *offset, size, fd, VVP_PARSE_PRO_FTPD) &&
                        !CheckVendorVersion(data, *offset, size, fd, VVP_PARSE_PURE_FTPD) &&
                        !CheckVendorVersion(data, *offset, size, fd, VVP_PARSE_NC_FTPD) &&
                        !CheckVendorVersion(data, *offset, size, fd, VVP_PARSE_FILEZILLA)
                        )
                    {
                        /* Look for (Vendor Version:  or  (Vendor Version) */
                        const unsigned char* end;
                        const unsigned char* p;
                        const unsigned char* ven;
                        const unsigned char* ver;
                        end = &data[size-1];
                        for (p=&data[*offset]; p<end && *p && *p!='('; p++)
                            ;
                        if (p < end)
                        {
                            p++;
                            ven = p;
                            for (; p<end && *p && *p!=' '; p++)
                                ;
                            if (p < end && *p)
                            {
                                CopyVendorString(fd, ven, p-ven);
                                ver = p + 1;
                                for (p=ver; p<end && *p && *p!=':'; p++)
                                    ;
                                if (p>=end || !(*p))
                                {
                                    for (p=ver; p<end && *p && *p!=')'; p++)
                                        ;
                                }
                                if (p < end && *p)
                                {
                                    CopyVersionString(fd, ver, p-ver);
                                }
                            }
                        }
                    }
                }
                else if (fd->code == 230)
                {
                    // These vendor strings are present on the first "230" whether that is the
                    // "230-" or "230 "
                    CheckVendorVersion(data, *offset, size, fd, VVP_PARSE_HP);
                }
            }

            fd->rstate = FTP_REPLY_MID;
            for (; *offset < size; (*offset)++)
            {
                if (data[*offset] == 0x0D)
                {
                    (*offset)++;
                    if (*offset >= size)
                        return -1;
                    if (data[*offset] == 0x0D)
                    {
                        (*offset)++;
                        if (*offset >= size)
                            return -1;
                    }
                    if (data[*offset] != 0x0A)
                        return -1;
                    fd->rstate = tmp_state;
                    break;
                }
                if (data[*offset] == 0x0A)
                {
                    fd->rstate = tmp_state;
                    break;
                }
            }
            if (fd->rstate == FTP_REPLY_MID)
                return -1;
            break;
        case FTP_REPLY_MULTI:
            if (size - *offset < (int)sizeof(ServiceFTPCode))
            {
                fd->rstate = FTP_REPLY_MID;
                for (; *offset < size; (*offset)++)
                {
                    if (data[*offset] == 0x0D)
                    {
                        (*offset)++;
                        if (*offset >= size)
                            return -1;
                        if (data[*offset] == 0x0D)
                        {
                            (*offset)++;
                            if (*offset >= size)
                                return -1;
                        }
                        if (data[*offset] != 0x0A)
                            return -1;
                        fd->rstate = FTP_REPLY_MULTI;
                        break;
                    }
                    if (data[*offset] == 0x0A)
                    {
                        fd->rstate = FTP_REPLY_MULTI;
                        break;
                    }
                }
                if (fd->rstate == FTP_REPLY_MID)
                    return -1;
            }
            else
            {
                code_hdr = (ServiceFTPCode*)(data + *offset);
                if (size - (*offset) >= (int)sizeof(ServiceFTPCode) &&
                    (code_hdr->sp == ' ' || code_hdr->sp == 0x09) &&
                    code_hdr->code[0] >= '1' && code_hdr->code[0] <= '5' &&
                    code_hdr->code[1] >= '1' && code_hdr->code[1] <= '5' &&
                    isdigit(code_hdr->code[2]))
                {
                    tmp = (code_hdr->code[0] - '0') * 100;
                    tmp += (code_hdr->code[1] - '0') * 10;
                    tmp += code_hdr->code[2] - '0';
                    if (tmp == fd->code)
                    {
                        *offset += sizeof(ServiceFTPCode);
                        fd->rstate = FTP_REPLY_BEGIN;
                    }
                }
                tmp_state = fd->rstate;
                fd->rstate = FTP_REPLY_MID;
                for (; *offset < size; (*offset)++)
                {
                    if (data[*offset] == 0x0D)
                    {
                        (*offset)++;
                        if (*offset >= size)
                            return -1;
                        if (data[*offset] == 0x0D)
                        {
                            (*offset)++;
                            if (*offset >= size)
                                return -1;
                        }
                        if (data[*offset] != 0x0A)
                            return -1;
                        fd->rstate = tmp_state;
                        break;
                    }
                    if (data[*offset] == 0x0A)
                    {
                        fd->rstate = tmp_state;
                        break;
                    }
                }
                if (fd->rstate == FTP_REPLY_MID)
                    return -1;
            }
            break;
        default:
            return -1;
        }
        if (fd->rstate == FTP_REPLY_BEGIN)
        {
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
                else if (!isspace(data[*offset]))
                    break;
            }
            return fd->code;
        }
    }
    return 0;
}

static inline int _ftp_decode_number32(const uint8_t** data, const uint8_t* end, uint8_t delimiter,
    uint32_t* number)
{
    const uint8_t* local_data;
    uint32_t local_number = 0;
    for (local_data = *data; local_data < end && *local_data == ' '; local_data++)
        ;
    if (local_data < end && *local_data == delimiter)
    {
        *number = 0;
        return -1;
    }
    while (local_data < end && *local_data != delimiter)
    {
        if (!isdigit(*local_data))
        {
            *number = 0;
            return -1;
        }
        local_number *= 10;
        local_number += *local_data - '0';
        local_data++;
    }
    if (local_data >= end || *local_data != delimiter)
    {
        *number = 0;
        return -1;
    }
    *number = local_number;
    *data = local_data+1;
    return 0;
}

static int ftp_decode_octet(const uint8_t** data, const uint8_t* end, uint8_t delimiter,
    uint32_t* number)
{
    if (_ftp_decode_number32(data, end, delimiter, number) == -1)
        return -1;
    if (*number > 255)
    {
        *number = 0;
        return -1;
    }
    return 0;
}

static int ftp_decode_port_number(const uint8_t** data, const uint8_t* end, uint8_t delimiter,
    uint32_t* number)
{
    if (_ftp_decode_number32(data, end, delimiter, number) == -1)
        return -1;
    if (*number > 65535)
    {
        *number = 0;
        return -1;
    }
    return 0;
}

static int ftp_validate_pasv(const uint8_t* data, uint16_t size,
    uint32_t* address, uint16_t* port)
{
    const uint8_t* end;
    uint32_t tmp;

    *address = 0;
    *port = 0;

    end = data + size;
    data += sizeof(ServiceFTPCode);

    for (; data<end && *data!='('; data++)
        ;
    data++;
    if (data >= end)
        return 1;

    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    *address = tmp << 24;
    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    *address += tmp << 16;
    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    *address += tmp << 8;
    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    *address += tmp;
    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    *port = (uint16_t)(tmp << 8);
    if (ftp_decode_octet(&data, end, ')', &tmp))
        return -1;
    *port += tmp;
    return 0;
}

static int ftp_validate_epsv(const uint8_t* data, uint16_t size,
    uint16_t* port)
{
    const uint8_t* end;
    uint8_t delimiter;

    *port = 0;

    end = data + size;
    data += sizeof(ServiceFTPCode);

    for (; data<end && *data!='('; data++)
        ;
    data++;
    if (data >= end)
        return 1;

    delimiter = *data++;
    if (data >= end)
        return 1;

    for (; data<end && *data!=delimiter; data++)
        ;
    data++;
    if (data >= end)
        return 1;

    for (; data<end && *data!=delimiter; data++)
        ;
    data++;
    if (data >= end)
        return 1;

    while (data < end && *data != delimiter)
    {
        if (!isdigit(*data))
            return -1;
        *port *= 10;
        *port += *data - '0';
        data++;
    }

    return 0;
}

static int ftp_validate_port(const uint8_t* data, uint16_t size,
    sfip_t* address, uint16_t* port)
{
    const uint8_t* end;
    const uint8_t* p;
    uint32_t tmp;
    uint32_t addr;
    uint32_t addr2;

    memset(address,0,sizeof(sfip_t));
    *port = 0;

    end = data + size;

    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    addr = tmp << 24;
    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    addr += tmp << 16;
    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    addr += tmp << 8;
    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    addr += tmp;
    addr2 = htonl(addr); // make it network order before calling sfip_set_raw()
    sfip_set_raw(address, &addr2, AF_INET);

    if (ftp_decode_octet(&data, end, ',', &tmp))
        return -1;
    *port = (uint16_t)(tmp << 8);
    p = end - 1;
    if (p > data)
    {
        if (*p == 0x0a)
        {
            p--;
            if (*p == 0x0d)
            {
                if (ftp_decode_octet(&data, end, 0x0d, &tmp))
                    return -1;
                *port += tmp;
                return 0;
            }
        }
    }
    if (ftp_decode_octet(&data, end, 0x0a, &tmp))
        return -1;
    *port += tmp;
    return 0;
}

/* RFC 2428 support */
struct  addr_family_map
{
    uint16_t eprt_fam;
    uint16_t sfaddr_fam;
};

static addr_family_map RFC2428_known_address_families[] =
{
    { 1, AF_INET },
    { 2, AF_INET6 },
    { 0, 0 }
};

static int ftp_validate_eprt(const uint8_t* data, uint16_t size,
    sfip_t* address, uint16_t* port)
{
    int index;
    int addrFamilySupported = 0;
    uint8_t delimiter;
    const uint8_t* end;
    uint32_t tmp;
    char tmp_str[INET6_ADDRSTRLEN+1];

    memset(address,0,sizeof(sfip_t));
    *port = 0;

    end = data + size;

    delimiter = *data++; // all delimiters will match this one.
    if (ftp_decode_octet(&data, end, delimiter, &tmp))
        return -1;

    // Look up the address family in the table.
    for (index = 0; !addrFamilySupported && RFC2428_known_address_families[index].eprt_fam != 0;
        index++)
    {
        if ( RFC2428_known_address_families[index].eprt_fam == (uint16_t)tmp )
        {
            addrFamilySupported = RFC2428_known_address_families[index].sfaddr_fam;
        }
    }
    if (!addrFamilySupported) // not an ipv4 or ipv6 address being provided.
        return -1;

    for (index = 0;
        index < INET6_ADDRSTRLEN && data < end && *data != delimiter;
        index++, data++ )
    {
        tmp_str[index] = *data;
    }
    tmp_str[index] = '\0'; // make the copied portion be nul terminated.

    if (sfip_convert_ip_text_to_binary(addrFamilySupported, tmp_str, &address) != SFIP_SUCCESS)
        return -1;

    address->family = addrFamilySupported;

    data++; // skip the delimiter at the end of the address substring.
    if (ftp_decode_port_number(&data, end, delimiter, &tmp)) // an error is returned if port was
                                                             // greater than 65535
        return -1;

    *port = (uint16_t)tmp;
    return 0;
}

static inline void WatchForCommandResult(ServiceFTPData* fd, AppIdData* flowp, FTPCmd command)
{
    if (fd->state != FTP_STATE_MONITOR)
    {
        setAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_CONTINUE);
        fd->state = FTP_STATE_MONITOR;
    }
    fd->cmd = command;
}

static inline void InitializeDataSession(AppIdData* flowp,AppIdData* fp)
{
    unsigned encryptedFlag = getAppIdFlag(flowp, APPID_SESSION_ENCRYPTED |
        APPID_SESSION_DECRYPTED);
    if (encryptedFlag == APPID_SESSION_ENCRYPTED)
    {
        fp->serviceAppId = APP_ID_FTPSDATA;
    }
    else
    {
        encryptedFlag = 0; // change (APPID_SESSION_ENCRYPTED | APPID_SESSION_DECRYPTED) case to
                           // zeroes.
        fp->serviceAppId = APP_ID_FTP_DATA;
    }
    PopulateExpectedFlow(flowp, fp, APPID_SESSION_IGNORE_ID_FLAGS | encryptedFlag);
}

static int ftp_validate(ServiceValidationArgs* args)
{
    static const char FTP_PASV_CMD[] = "PASV";
    static const char FTP_EPSV_CMD[] = "EPSV";
    static const char FTP_PORT_CMD[] = "PORT ";
    static const char FTP_EPRT_CMD[] = "EPRT ";
    ServiceFTPData* fd;
    uint16_t offset;
    uint16_t init_offset;
    int code;
    int code_index;
    uint32_t address;
    uint16_t port;
    AppIdData* fp;
    int retval = SERVICE_INPROCESS;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;

    //ignore packets while encryption is on in explicit mode. In future, this will be changed
    //to direct traffic to SSL detector to extract payload from certs. This will require
    // manintaining
    //two detector states at the same time.
    if (getAppIdFlag(flowp, APPID_SESSION_ENCRYPTED))
    {
        if (!getAppIdFlag(flowp, APPID_SESSION_DECRYPTED))
        {
            goto inprocess;
        }
    }

    fd = (ServiceFTPData*)ftp_service_mod.api->data_get(flowp, ftp_service_mod.flow_data_index);
    if (!fd)
    {
        fd = (ServiceFTPData*)snort_calloc(sizeof(ServiceFTPData));
        ftp_service_mod.api->data_add(flowp, fd, ftp_service_mod.flow_data_index, &snort_free);
        fd->state = FTP_STATE_CONNECTION;
        fd->rstate = FTP_REPLY_BEGIN;
        fd->cmd = FTP_CMD_NONE;
    }

    if (dir != APP_ID_FROM_RESPONDER)
    {
        if (data[size-1] != 0x0a)
            goto inprocess;

        if (size > sizeof(FTP_PORT_CMD)-1 &&
            strncasecmp((char*)data, FTP_PORT_CMD, sizeof(FTP_PORT_CMD)-1) == 0)
        {
            if (ftp_validate_port(data+(sizeof(FTP_PORT_CMD)-1),
                size-(sizeof(FTP_PORT_CMD)-1),
                &fd->address, &fd->port) == 0)
            {
                WatchForCommandResult(fd, flowp, FTP_CMD_PORT_EPRT);
            }
        }
        else if (size > sizeof(FTP_EPRT_CMD)-1 &&
            strncasecmp((char*)data, FTP_EPRT_CMD, sizeof(FTP_EPRT_CMD)-1) == 0)
        {
            if (ftp_validate_eprt(data+(sizeof(FTP_EPRT_CMD)-1),
                size-(sizeof(FTP_EPRT_CMD)-1),
                &fd->address, &fd->port) == 0)
            {
                WatchForCommandResult(fd, flowp, FTP_CMD_PORT_EPRT);
            }
        }
        else if ( size > sizeof(FTP_PASV_CMD)-1 &&
            ( strncasecmp((char*)data, FTP_PASV_CMD, sizeof(FTP_PASV_CMD)-1) == 0 ||
            strncasecmp((char*)data, FTP_EPSV_CMD, sizeof(FTP_EPSV_CMD)-1) == 0 )
            )
        {
            WatchForCommandResult(fd, flowp, FTP_CMD_PASV_EPSV);
        }
        goto inprocess;
    }

    offset = 0;
    while (offset < size)
    {
        init_offset = offset;
        if ((code=ftp_validate_reply(data, &offset, size, fd)) < 0)
            goto fail;
        if (!code)
            goto inprocess;

        switch (fd->state)
        {
        case FTP_STATE_CONNECTION:
            switch (code)
            {
            case 120: /*system will be ready in nn minutes */
                break;
            case 220: /*service ready for new user */
                fd->state = FTP_STATE_LOGIN;
                break;
            case 110: /* restart mark reply */
            case 125: /* connection is open start transferring file */
            case 150: /* Opening command */
            case 200: /*command ok */
            case 202: /*command not implemented */
            case 211: /* system status */
            case 212: /* directory status */
            case 213: /* file status */
            case 214: /* help message */
            case 215: /* name system type */
            case 225: /* data connection open */
            case 226: /* Transfer complete */
            case 227: /*entering passive mode */
            case 230: /*user loggined */
            case 250: /* CWD command successful */
            case 257: /* PATHNAME created */
            case 331: /* login ok need password */
            case 332: /*new account for login */
            case 350: /*requested file action pending futher information */
            case 450: /*requested file action not taken */
            case 451: /*requested file action aborted */
            case 452: /*requested file action not taken not enough space */
            case 500: /*syntax error */
            case 501: /*not recognozed */
            case 502: /*not recognozed */
            case 503: /*bad sequence of commands */
            case 504: /*command not implemented */
            case 530: /*login incorrect */
            case 532: /*new account for storing file */
            case 550: /*requested action not taken */
            case 551: /*requested action aborted :page type unknown */
            case 552: /*requested action aborted */
            case 553: /*requested action not taken file name is not allowed */
                setAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_CONTINUE);
                fd->state = FTP_STATE_MONITOR;
                break;
            case 221: /*good bye */
            case 421: /*service not available closing connection */
                fd->state = FTP_STATE_CONNECTION_ERROR;
                break;
            default:
                goto fail;
            }
            break;
        case FTP_STATE_LOGIN:
            code_index = code / 100;
            switch (code_index)
            {
            case 2:
                switch (code)
                {
                case 221:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                case 230:
                    setAppIdFlag(flowp, APPID_SESSION_CONTINUE);
                    fd->state = FTP_STATE_MONITOR;
                    retval = SERVICE_SUCCESS;
                    break;
                case 234:
                {
                    setAppIdFlag(flowp, APPID_SESSION_CONTINUE);
                    retval = SERVICE_SUCCESS;
                    /*
                    // we do not set the state to FTP_STATE_MONITOR here because we don't know
                    // if there will be SSL decryption to allow us to see what we are interested in.
                    // Let the WatchForCommandResult() usage elsewhere take care of it.
                    */
                    setAppIdFlag(flowp,
                        APPID_SESSION_CONTINUE |
                        APPID_SESSION_ENCRYPTED |
                        APPID_SESSION_STICKY_SERVICE);
                }
                break;
                default:
                    break;
                }
                break;
            case 3:
                switch (code)
                {
                case 331:
                    fd->state = FTP_STATE_PASSWORD;
                    break;
                case 332:
                    fd->state = FTP_STATE_ACCOUNT;
                    break;
                default:
                    break;
                }
                break;
            case 4:
                switch (code)
                {
                case 421:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                case 431:
                    break;
                default:
                    goto fail;
                }
                break;
            case 5:
                break;
            default:
                goto fail;
            }
            break;
        case FTP_STATE_PASSWORD:
            code_index = code / 100;
            switch (code_index)
            {
            case 2:
                switch (code)
                {
                case 221:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                case 202:
                case 230:
                    setAppIdFlag(flowp, APPID_SESSION_CONTINUE);
                    fd->state = FTP_STATE_MONITOR;
                    retval = SERVICE_SUCCESS;
                default:
                    break;
                }
                break;
            case 3:
                switch (code)
                {
                case 332:
                    fd->state = FTP_STATE_ACCOUNT;
                    break;
                default:
                    break;
                }
                break;
            case 4:
                switch (code)
                {
                case 421:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                default:
                    goto fail;
                }
                break;
            case 5:
                switch (code)
                {
                case 500:
                case 501:
                case 503:
                case 530:
                    fd->state = FTP_STATE_LOGIN;
                    break;
                default:
                    goto fail;
                }
                break;
            default:
                goto fail;
            }
            break;
        case FTP_STATE_ACCOUNT:
            code_index = code / 100;
            switch (code_index)
            {
            case 2:
                switch (code)
                {
                case 202:
                case 230:
                    setAppIdFlag(flowp, APPID_SESSION_CONTINUE);
                    fd->state = FTP_STATE_MONITOR;
                    retval = SERVICE_SUCCESS;
                default:
                    break;
                }
                break;
            case 3:
                switch (code)
                {
                case 332:
                    fd->state = FTP_STATE_ACCOUNT;
                    break;
                default:
                    break;
                }
                break;
            case 4:
                switch (code)
                {
                case 421:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                default:
                    goto fail;
                }
                break;
            case 5:
                switch (code)
                {
                case 500:
                case 501:
                case 503:
                case 530:
                    fd->state = FTP_STATE_LOGIN;
                    break;
                default:
                    goto fail;
                }
                break;
            default:
                goto fail;
            }
            break;
        case FTP_STATE_MONITOR: // looking for the DATA channel info in the result
            switch (code)
            {
            case 227:
            {
                code = ftp_validate_pasv(data + init_offset,
                    (uint16_t)(offset-init_offset),
                    &address, &port);
                if (!code)
                {
                    sfip_t ip;
                    const sfip_t* sip;
                    const sfip_t* dip;
                    uint32_t addr;

                    dip = pkt->ptrs.ip_api.get_dst();
                    sip = pkt->ptrs.ip_api.get_src();
                    addr = htonl(address);
                    sfip_set_raw(&ip, &addr, AF_INET);
                    fp = ftp_service_mod.api->flow_new(flowp, pkt, dip, 0, &ip, port, flowp->proto,
                        ftp_data_app_id,
                        APPID_EARLY_SESSION_FLAG_FW_RULE);
                    if (fp)
                    {
                        InitializeDataSession(flowp,fp);
                    }
                    if (!sfip_fast_eq6(&ip, sip))
                    {
                        fp = ftp_service_mod.api->flow_new(flowp, pkt, dip, 0, sip, port,
                            flowp->proto, ftp_data_app_id,
                            APPID_EARLY_SESSION_FLAG_FW_RULE);
                        if (fp)
                        {
                            InitializeDataSession(flowp,fp);
                        }
                    }
                    ftp_service_mod.api->add_payload(flowp, APP_ID_FTP_PASSIVE);     // Passive
                                                                                     // mode FTP is
                                                                                     // reported as
                                                                                     // a payload
                                                                                     // id
                }
                else if (code < 0)
                {
                    goto fail;
                }
            }
            break;
            case 229:
            {
                code = ftp_validate_epsv(data + init_offset,
                    (uint16_t)(offset-init_offset),
                    &port);

                if (!code)
                {
                    const sfip_t* sip;
                    const sfip_t* dip;
                    dip = pkt->ptrs.ip_api.get_dst();
                    sip = pkt->ptrs.ip_api.get_src();
                    fp = ftp_service_mod.api->flow_new(flowp, pkt, dip, 0, sip, port, flowp->proto,
                        ftp_data_app_id,
                        APPID_EARLY_SESSION_FLAG_FW_RULE);
                    if (fp)
                    {
                        InitializeDataSession(flowp,fp);
                    }
                    ftp_service_mod.api->add_payload(flowp, APP_ID_FTP_PASSIVE);     // Passive
                                                                                     // mode FTP is
                                                                                     // reported as
                                                                                     // a payload
                                                                                     // id
                }
                else if (code < 0)
                {
                    goto fail;
                }
            }
            break;
            case 200:
                if (fd->cmd == FTP_CMD_PORT_EPRT)
                {
                    const sfip_t* sip;
                    sip = pkt->ptrs.ip_api.get_src();
                    fp = ftp_service_mod.api->flow_new(flowp, pkt, sip, 0, &fd->address, fd->port,
                        flowp->proto, ftp_data_app_id,
                        APPID_EARLY_SESSION_FLAG_FW_RULE);
                    if (fp)
                    {
                        InitializeDataSession(flowp,fp);
                    }
                    ftp_service_mod.api->add_payload(flowp, APP_ID_FTP_ACTIVE); // Active mode FTP
                                                                                // is reported as a
                                                                                // payload id
                }
                break;
            default:
                break;
            }
            fd->cmd = FTP_CMD_NONE;
            break;
        case FTP_STATE_CONNECTION_ERROR:
        default:
            goto fail;
        }
    }

    switch (retval)
    {
    default:
    case SERVICE_INPROCESS:
inprocess:
        if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
        {
            ftp_service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
        }
        return SERVICE_INPROCESS;

    case SERVICE_SUCCESS:
        if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
        {
            uint64_t encryptedFlag = getAppIdFlag(flowp, 
                APPID_SESSION_ENCRYPTED | APPID_SESSION_DECRYPTED);

            // FTPS only when encrypted==1 decrypted==0
            ftp_service_mod.api->add_service(flowp, pkt, dir, &svc_element,
                encryptedFlag == APPID_SESSION_ENCRYPTED ?
                APP_ID_FTPS : APP_ID_FTP_CONTROL,
                fd->vendor[0] ? fd->vendor : nullptr,
                fd->version[0] ? fd->version : nullptr, nullptr);

            if(encryptedFlag == APPID_SESSION_ENCRYPTED)
                appid_stats.ftps_flows++;
            else
                appid_stats.ftp_flows++;
        }
        return SERVICE_SUCCESS;

    case SERVICE_NOMATCH:
fail:
        if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
        {
            ftp_service_mod.api->fail_service(flowp, pkt, dir, &svc_element,
                ftp_service_mod.flow_data_index, args->pConfig);
        }
        clearAppIdFlag(flowp, APPID_SESSION_CONTINUE);
        return SERVICE_NOMATCH;
    }
}

