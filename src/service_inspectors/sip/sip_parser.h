//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc
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

// sip_parser.h author Hui Cao <huica@cisco.com>

#ifndef SIP_PARSER_H
#define SIP_PARSER_H

// functions for parsing and querying SIP configuration

#include "sip_config.h"

struct SIP_DialogID
{
    uint32_t callIdHash;
    uint32_t fromTagHash;
    uint32_t toTagHash;
};

struct SIPMsg
{
    uint16_t headerLen;
    uint16_t methodLen;
    SIPMethodsFlag methodFlag;
    uint16_t status_code;

    uint16_t uriLen;
    uint16_t callIdLen;
    uint16_t cseqNameLen;
    uint16_t fromLen;
    uint16_t fromTagLen;
    uint16_t toLen;
    uint16_t toTagLen;
    uint16_t viaLen;
    uint16_t contactLen;
    uint16_t bodyLen;
    uint16_t contentTypeLen;
    uint32_t content_len;
    SIP_DialogID dlgID;
    SIP_MediaSession* mediaSession;
    const char* authorization;
    const uint8_t* header;
    const uint8_t* body_data; // Set to NULL if not applicable
    uint64_t cseqnum;

    uint16_t userNameLen;
    uint16_t userAgentLen;
    uint16_t serverLen;
    bool mediaUpdated;

    // nothing after this point is zeroed ...  Input parameters
    unsigned char isTcp;
    const char* method;
    const char* uri;
    const char* call_id;
    const char* cseqName;
    const char* from;
    const char* from_tag;
    const char* to;
    const char* to_tag;
    const char* via;
    const char* contact;

    const char* content_type;
    const char* content_encode;

    const char* userAgent;
    const char* userName;
    const char* server;
};

#define SIPMSG_ZERO_LEN offsetof(SIPMsg, isTcp)

#define MAX_STAT_CODE      999
#define MIN_STAT_CODE      100

bool sip_parse(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
void sip_freeMsg(SIPMsg* msg);
void sip_freeMediaSession(SIP_MediaSession*);
void sip_freeMediaList(SIP_MediaList medias);

#endif

