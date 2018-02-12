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

// sip_config.h author Hui Cao <huica@cisco.com>

#ifndef SIP_CONFIG_H
#define SIP_CONFIG_H

// Configuration for SIP service inspector

#include "framework/counts.h"
#include "main/thread.h"
#include "sip_common.h"

#define SIP_METHOD_DEFAULT     0x003f
#define SIP_METHOD_ALL     0xffffffff

#define SIP_STATUS_CODE_LEN (3)
#define SIP_CONTENT_LEN (5)

#define METHOD_NOT_FOUND (-1)

#define SIP_SESSION_SAVED   (1)
#define SIP_SESSION_INIT    (0)

#define SIP_DEFAULT_MAX_SESSIONS            10000
#define SIP_DEFAULT_MAX_DIALOGS_IN_SESSION  4
#define SIP_DEFAULT_MAX_URI_LEN             256
#define SIP_DEFAULT_MAX_CALL_ID_LEN         256
#define SIP_DEFAULT_MAX_REQUEST_NAME_LEN    20
#define SIP_DEFAULT_MAX_FROM_LEN            256
#define SIP_DEFAULT_MAX_TO_LEN              256
#define SIP_DEFAULT_MAX_VIA_LEN             1024
#define SIP_DEFAULT_MAX_CONTACT_LEN         256
#define SIP_DEFAULT_MAX_CONTENT_LEN         1024
#define NUM_OF_RESPONSE_TYPES  10
#define NUM_OF_REQUEST_TYPES  SIP_METHOD_USER_DEFINE

struct SipStats
{
    PegCount packets;
    PegCount sessions;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
    PegCount events;
    PegCount dialogs;
    PegCount ignoreChannels;
    PegCount ignoreSessions;
    PegCount requests[NUM_OF_REQUEST_TYPES];
    PegCount responses[NUM_OF_RESPONSE_TYPES];
};

extern THREAD_LOCAL SipStats sip_stats;


// Header fields and processing functions
struct SIPMethod
{
    const char* name;
    SIPMethodsFlag methodFlag;
};

extern SIPMethod StandardMethods[];

struct SIPMethodNode
{
    char* methodName;
    int methodLen;
    SIPMethodsFlag methodFlag;
    SIPMethodNode* nextm;
};

typedef SIPMethodNode* SIPMethodlist;

// SIP configuration.

struct SIP_PROTO_CONF
{
    uint32_t maxNumDialogsInSession;
    uint32_t methodsConfig;
    SIPMethodlist methods;   // Which methods to check
    uint16_t maxUriLen;      // Maximum request_URI size
    uint16_t maxCallIdLen;   // Maximum call_ID size.
    uint16_t maxRequestNameLen;  // Maximum length of request name in the CSeqID.
    uint16_t maxFromLen;     // Maximum From field size
    uint16_t maxToLen;       // Maximum To field size
    uint16_t maxViaLen;      // Maximum Via field size
    uint16_t maxContactLen;  // Maximum Contact field size
    uint16_t maxContentLen;  // Maximum Content length
    bool ignoreChannel;   // Whether to ignore media channels found by SIP PP
};

// API to parse method list
void SIP_ParseMethods(
    const char* cur_tokenp, uint32_t* methodsConfig, SIPMethodlist* pmethods);

// Sets the Default method lists
void SIP_SetDefaultMethods(SIP_PROTO_CONF* config);

// API to add a user defined method to SIP config
SIPMethodNode* SIP_AddUserDefinedMethod(
    const char* methodName, uint32_t* methodsConfig, SIPMethodlist* pmethods);

// API to delete a method from SIP config
void SIP_DeleteMethods(SIPMethodNode*);

#endif

