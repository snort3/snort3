//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// sip_common.h author Hui Cao <huica@cisco.com>

#ifndef SIP_COMMON_H
#define SIP_COMMON_H

#include "sfip/sf_ip.h"

// Header containing datatypes/definitions shared by SIP inspector files.

enum SIPMethodsFlag
{
    SIP_METHOD_NULL        = 0,    // 0x0000,
    SIP_METHOD_INVITE      = 1,    // 0x0001,
    SIP_METHOD_CANCEL      = 2,    // 0x0002,
    SIP_METHOD_ACK         = 3,    // 0x0004,
    SIP_METHOD_BYE         = 4,    // 0x0008,
    SIP_METHOD_REGISTER    = 5,    // 0x0010,
    SIP_METHOD_OPTIONS     = 6,    // 0x0020,
    SIP_METHOD_REFER       = 7,    // 0x0040,
    SIP_METHOD_SUBSCRIBE   = 8,    // 0x0080,
    SIP_METHOD_UPDATE      = 9,    // 0x0100,
    SIP_METHOD_JOIN        = 10,   // 0x0200,
    SIP_METHOD_INFO        = 11,   // 0x0400,
    SIP_METHOD_MESSAGE     = 12,   // 0x0800,
    SIP_METHOD_NOTIFY      = 13,   // 0x1000,
    SIP_METHOD_PRACK       = 14,   // 0x2000,
    SIP_METHOD_USER_DEFINE = 15,   // 0x4000,
    SIP_METHOD_USER_DEFINE_MAX = 32// 0x80000000,
};

struct SipHeaders
{
    const char* callid;
    const char* from;
    const char* userAgent;
    const char* server;
    const char* userName;
    uint16_t callidLen;
    uint16_t fromLen;
    uint16_t userAgentLen;
    uint16_t serverLen;
    uint16_t userNameLen;

    SIPMethodsFlag methodFlag;
};

enum SIP_DialogState
{
    SIP_DLG_CREATE = 1,   // 1
    SIP_DLG_INVITING,     // 2
    SIP_DLG_EARLY,        // 3
    SIP_DLG_AUTHENCATING, // 4
    SIP_DLG_ESTABLISHED,  // 5
    SIP_DLG_REINVITING,   // 6
    SIP_DLG_TERMINATING,  // 7
    SIP_DLG_TERMINATED    // 8
};

struct SIP_MediaData
{
    snort::SfIp maddress;  // media IP
    uint16_t mport;   // media port
    uint8_t numPort;   // number of media ports
    SIP_MediaData* nextM;
} ;

typedef SIP_MediaData* SIP_MediaDataList;

struct SIP_MediaSession
{
    uint32_t sessionID; // a hash value of the session
    int savedFlag;      // whether this data has been saved by a dialog,
                        // if savedFlag = 1, this session will be deleted after sip message is
                        // processed.
    snort::SfIp maddress_default;  // Default media IP
    SIP_MediaDataList medias; // Media list in the session
    SIP_MediaSession* nextS; // Next media session
};

typedef SIP_MediaSession* SIP_MediaList;

struct SipDialog
{
    SIP_DialogState state;
    SIP_MediaList mediaSessions;
    bool mediaUpdated;
};

#endif

