//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// pop.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef POP_H
#define POP_H

// Implementation header with definitions, datatypes and flowdata class for
// POP service inspector.

#include "flow/flow.h"
#include "mime/file_mime_process.h"

// Direction packet is coming from, if we can figure it out
#define POP_PKT_FROM_UNKNOWN  0
#define POP_PKT_FROM_CLIENT   1
#define POP_PKT_FROM_SERVER   2

#define STATE_DATA             0    // Data state 
#define STATE_TLS_CLIENT_PEND  1    // Got STARTTLS
#define STATE_TLS_SERVER_PEND  2    // Got STARTTLS
#define STATE_TLS_DATA         3    // Successful handshake, TLS encrypted data
#define STATE_COMMAND          4
#define STATE_UNKNOWN          5

// session flags
#define POP_FLAG_NEXT_STATE_UNKNOWN         0x00000004
#define POP_FLAG_GOT_NON_REBUILT            0x00000008
#define POP_FLAG_CHECK_SSL                  0x00000010

typedef enum _POPCmdEnum
{
    CMD_APOP = 0,
    CMD_AUTH,
    CMD_CAPA,
    CMD_DELE,
    CMD_LIST,
    CMD_NOOP,
    CMD_PASS,
    CMD_QUIT,
    CMD_RETR,
    CMD_RSET,
    CMD_STAT,
    CMD_STLS,
    CMD_TOP,
    CMD_UIDL,
    CMD_USER,
    CMD_LAST
} POPCmdEnum;

typedef enum _POPRespEnum
{
    RESP_OK = 1,
    RESP_ERR,
    RESP_LAST
} POPRespEnum;

typedef enum _POPHdrEnum
{
    HDR_CONTENT_TYPE = 0,
    HDR_CONT_TRANS_ENC,
    HDR_CONT_DISP,
    HDR_LAST
} POPHdrEnum;

struct POPSearch
{
    const char* name;
    int name_len;
};

struct POPToken
{
    const char* name;
    int name_len;
    int search_id;
};

struct POPSearchInfo
{
    int id;
    int index;
    int length;
};

class PopMime : public snort::MimeSession
{
    using snort::MimeSession::MimeSession;
private:
    void decode_alert() override;
    void reset_state(snort::Flow* ssn) override;
    bool is_end_of_data(snort::Flow* ssn) override;
};

struct POPData
{
    int state;
    int prev_response;
    int state_flags;
    int session_flags;
    PopMime* mime_ssn;
};

class PopFlowData : public snort::FlowData
{
public:
    PopFlowData();
    ~PopFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    POPData session;
};

#endif
