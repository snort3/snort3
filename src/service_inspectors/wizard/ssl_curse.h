//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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
// ssl_curse.h author Maya Dagon <mdagon@cisco.com>
// Refactored from curses.h

#ifndef SSL_CURSE_H
#define SSL_CURSE_H

// SSL curse helps determine if the traffic being processed is SSL

enum SSL_State
{
    SSL_STATE__BYTE_0_LEN_MSB = 0,
    SSL_STATE__BYTE_1_LEN_LSB,
    SSL_STATE__BYTE_2_CLIENT_HELLO,
    SSL_STATE__BYTE_3_MAX_MINOR_VER,
    SSL_STATE__BYTE_4_V3_MAJOR,
    SSL_STATE__BYTE_5_SPECS_LEN_MSB,
    SSL_STATE__BYTE_6_SPECS_LEN_LSB,
    SSL_STATE__BYTE_7_SSNID_LEN_MSB,
    SSL_STATE__BYTE_8_SSNID_LEN_LSB,
    SSL_STATE__BYTE_9_CHLNG_LEN_MSB,
    SSL_STATE__BYTE_10_CHLNG_LEN_LSB,
    SSL_STATE__SSL_FOUND,
    SSL_STATE__SSL_NOT_FOUND
};

class SslTracker
{
public:
    SSL_State state = SSL_STATE__BYTE_0_LEN_MSB;
    unsigned total_len;
    unsigned ssnid_len;
    unsigned specs_len;
    unsigned chlng_len;
};

#endif
