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

// appid.h author Sourcefire Inc.

#ifndef APPID_H
#define APPID_H

#include "thirdparty_appid_types.h"

#define SF_APPID_MAX            40000
#define SF_APPID_BUILDIN_MAX    30000
#define APPID_MAX_PRIORITY      3
#define SF_APPID_CSD_MIN        1000000
#define SF_APPID_DYNAMIC_MIN    2000000
#define NUMBER_OF_PTYPES        9

// FIXIT-H J stuff like this needs to be defined in config.h
#define RESPONSE_CODE_PACKET_THRESHHOLD 0

// FIXIT-L J properly scoped enum would be more appropriate
enum APPID_SESSION_DIRECTION
{
    APP_ID_FROM_INITIATOR,
    APP_ID_FROM_RESPONDER,
    APP_ID_APPID_SESSION_DIRECTION_MAX // Maximum value of a direction (must be last in the list)
};

// FIXIT-M J this doesn't seem appropriate for an enum
enum SERVICE_HOST_INFO_CODE
{
    SERVICE_HOST_INFO_NETBIOS_NAME = 1
};

// FIXIT-M J this should go in a separate header
#define DHCP_OPTION55_LEN_MAX 255

// FIXIT-M J this should go in a separate header
#define FINGERPRINT_UDP_FLAGS_XENIX 0x00000800
#define FINGERPRINT_UDP_FLAGS_NT    0x00001000
#define FINGERPRINT_UDP_FLAGS_MASK  (FINGERPRINT_UDP_FLAGS_XENIX | FINGERPRINT_UDP_FLAGS_NT)

#endif

