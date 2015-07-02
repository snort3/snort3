//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
//

//Author: Hui Cao <huica@cisco.com>

#ifndef SIP_CONFIG_H
#define SIP_CONFIG_H

#include "protocols/packet.h"
#include "sip_common.h"
#include "framework/counts.h"
#include "main/thread.h"

#define SIP_METHOD_DEFAULT     0x003f
#define SIP_METHOD_ALL     0xffffffff

#define SIP_STATUS_CODE_LEN (3)
#define SIP_CONTENT_LEN (5)

#define METHOD_NOT_FOUND -1

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
#define NUM_OF_REQUEST_TYPES  SIP_METHOD_USER_DEFINE_MAX

struct SIP_Stats
{
    PegCount sessions;
    PegCount events;

    PegCount dialogs;
    PegCount ignoreChannels;
    PegCount ignoreSessions;
    PegCount requests; // [NUM_OF_REQUEST_TYPES];    // FIXIT-L support this
    PegCount responses; // [NUM_OF_RESPONSE_TYPES];  // FIXIT-L support this
};

extern THREAD_LOCAL SIP_Stats sip_stats;

/*
   * Header fields and processing functions
    */
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
    struct SIPMethodNode* nextm;
};

typedef SIPMethodNode* SIPMethodlist;

/*
* SIP configuration.
*
* maxNumSessions: Maximum amount of run-time memory
* methods: Which methods to check
* maxUriLen: Maximum requst_URI size
* maxCallIdLen: Maximum call_ID size.
* maxRequestNameLen: Maximum length of request name in the CSeqID.
* maxFromLen: Maximum From field size
* maxToLen: Maximum To field size
* maxViaLen: Maximum Via field size
* maxContactLen: Maximum Contact field size
* maxContentLen: Maximum Content length
* ignoreChannel: Whether to ignore media channels found by SIP PP
*/
struct SIP_PROTO_CONF
{
    uint32_t maxNumSessions;
    uint32_t maxNumDialogsInSession;
    uint32_t methodsConfig;
    SIPMethodlist methods;
    uint16_t maxUriLen;
    uint16_t maxCallIdLen;
    uint16_t maxRequestNameLen;
    uint16_t maxFromLen;
    uint16_t maxToLen;
    uint16_t maxViaLen;
    uint16_t maxContactLen;
    uint16_t maxContentLen;
    uint8_t ignoreChannel;
};
void SIP_ParseMethods(char* cur_tokenp, uint32_t* methodsConfig, SIPMethodlist* pmethods);
void SIP_SetDefaultMethods(SIP_PROTO_CONF* config);
int SIP_findMethod(char* token, SIPMethod* methods);
SIPMethodNode* SIP_AddUserDefinedMethod(char* methodName, uint32_t* methodsConfig, SIPMethodlist* pmethods);

#endif

