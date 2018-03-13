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

// sip_dialog.h author Hui Cao <huica@cisco.com>

#ifndef SIP_DIALOG_H
#define SIP_DIALOG_H

// Dialog management for SIP call flow analysis

#include "sip_parser.h"

namespace snort
{
struct Packet;
}

#define TOTAL_RESPONSES 0
#define RESPONSE1XX     1
#define RESPONSE2XX     2
#define RESPONSE3XX     3
#define RESPONSE4XX     4
#define RESPONSE5XX     5
#define RESPONSE6XX     6
#define TOTAL_REQUESTS 0

struct SIP_DialogData
{
    SIP_DialogID dlgID;
    SIP_DialogState state;
    SIPMethodsFlag creator;
    uint16_t status_code;
    SIP_MediaList mediaSessions;
    struct SIP_DialogData* nextD;
    struct SIP_DialogData* prevD;
};

struct SIP_DialogList
{
    SIP_DialogData* head;
    uint32_t num_dialogs;
};

int SIP_updateDialog(SIPMsg* sipMsg, SIP_DialogList* dList, snort::Packet* p, SIP_PROTO_CONF*);
void sip_freeDialogs(SIP_DialogList* list);

#endif

