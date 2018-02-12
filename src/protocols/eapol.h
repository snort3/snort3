//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// eapol.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_EAPOL_H
#define PROTOCOLS_EAPOL_H

namespace eapol
{
struct EtherEapol
{
    uint8_t version;   /* EAPOL proto version */
    uint8_t eaptype;   /* EAPOL Packet type */
    uint16_t len;  /* Packet body length */
};

struct EAPHdr
{
    uint8_t code;
    uint8_t id;
    uint16_t len;
};

struct EapolKey
{
    uint8_t type;
    uint8_t length[2];
    uint8_t counter[8];
    uint8_t iv[16];
    uint8_t index;
    uint8_t sig[16];
};

/* IEEE 802.1x eapol types */
#define EAPOL_TYPE_EAP      0x00      /* EAP packet */
#define EAPOL_TYPE_START    0x01      /* EAPOL start */
#define EAPOL_TYPE_LOGOFF   0x02      /* EAPOL Logoff */
#define EAPOL_TYPE_KEY      0x03      /* EAPOL Key */
#define EAPOL_TYPE_ASF      0x04      /* EAPOL Encapsulated ASF-Alert */

/* Extensible Authentication Protocol Codes RFC 2284*/
#define EAP_CODE_REQUEST    0x01
#define EAP_CODE_RESPONSE   0x02
#define EAP_CODE_SUCCESS    0x03
#define EAP_CODE_FAILURE    0x04
/* EAP Types */
#define EAP_TYPE_IDENTITY   0x01
#define EAP_TYPE_NOTIFY     0x02
#define EAP_TYPE_NAK        0x03
#define EAP_TYPE_MD5        0x04
#define EAP_TYPE_OTP        0x05
#define EAP_TYPE_GTC        0x06
#define EAP_TYPE_TLS        0x0d

/* Extensible Authentication Protocol Codes RFC 2284*/
#define EAP_CODE_REQUEST    0x01
#define EAP_CODE_RESPONSE   0x02
#define EAP_CODE_SUCCESS    0x03
#define EAP_CODE_FAILURE    0x04
/* EAP Types */
#define EAP_TYPE_IDENTITY   0x01
#define EAP_TYPE_NOTIFY     0x02
#define EAP_TYPE_NAK        0x03
#define EAP_TYPE_MD5        0x04
#define EAP_TYPE_OTP        0x05
#define EAP_TYPE_GTC        0x06
#define EAP_TYPE_TLS        0x0d
}

#endif /* EAPOL_H */

