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

// imap.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef IMAP_H
#define IMAP_H

// Implementation header with definitions, datatypes and flowdata class for
// IMAP service inspector.

#include "flow/flow.h"
#include "mime/file_mime_process.h"

// Direction packet is coming from, if we can figure it out
#define IMAP_PKT_FROM_UNKNOWN  0
#define IMAP_PKT_FROM_CLIENT   1
#define IMAP_PKT_FROM_SERVER   2

#define STATE_DATA             0    // Data state
#define STATE_TLS_CLIENT_PEND  1    // Got STARTTLS
#define STATE_TLS_SERVER_PEND  2    // Got STARTTLS
#define STATE_TLS_DATA         3    // Successful handshake, TLS encrypted data
#define STATE_COMMAND          4
#define STATE_UNKNOWN          5

// session flags
#define IMAP_FLAG_NEXT_STATE_UNKNOWN         0x00000004
#define IMAP_FLAG_GOT_NON_REBUILT            0x00000008
#define IMAP_FLAG_CHECK_SSL                  0x00000010

typedef enum _IMAPCmdEnum
{
    CMD_APPEND = 0,
    CMD_AUTHENTICATE,
    CMD_CAPABILITY,
    CMD_CHECK,
    CMD_CLOSE,
    CMD_COMPARATOR,
    CMD_COMPRESS,
    CMD_CONVERSIONS,
    CMD_COPY,
    CMD_CREATE,
    CMD_DELETE,
    CMD_DELETEACL,
    CMD_DONE,
    CMD_EXAMINE,
    CMD_EXPUNGE,
    CMD_FETCH,
    CMD_GETACL,
    CMD_GETMETADATA,
    CMD_GETQUOTA,
    CMD_GETQUOTAROOT,
    CMD_IDLE,
    CMD_LIST,
    CMD_LISTRIGHTS,
    CMD_LOGIN,
    CMD_LOGOUT,
    CMD_LSUB,
    CMD_MYRIGHTS,
    CMD_NOOP,
    CMD_NOTIFY,
    CMD_RENAME,
    CMD_SEARCH,
    CMD_SELECT,
    CMD_SETACL,
    CMD_SETMETADATA,
    CMD_SETQUOTA,
    CMD_SORT,
    CMD_STARTTLS,
    CMD_STATUS,
    CMD_STORE,
    CMD_SUBSCRIBE,
    CMD_THREAD,
    CMD_UID,
    CMD_UNSELECT,
    CMD_UNSUBSCRIBE,
    CMD_X,
    CMD_LAST
} IMAPCmdEnum;

typedef enum _IMAPRespEnum
{
    RESP_CAPABILITY = 0,
    RESP_LIST,
    RESP_LSUB,
    RESP_STATUS,
    RESP_SEARCH,
    RESP_FLAGS,
    RESP_EXISTS,
    RESP_RECENT,
    RESP_EXPUNGE,
    RESP_FETCH,
    RESP_BAD,
    RESP_BYE,
    RESP_NO,
    RESP_OK,
    RESP_PREAUTH,
    RESP_ENVELOPE,
    RESP_UID,
    RESP_LAST
} IMAPRespEnum;

typedef enum _IMAPHdrEnum
{
    HDR_CONTENT_TYPE = 0,
    HDR_CONT_TRANS_ENC,
    HDR_CONT_DISP,
    HDR_LAST
} IMAPHdrEnum;

struct IMAPSearch
{
    const char* name;
    int name_len;
};

struct IMAPToken
{
    const char* name;
    int name_len;
    int search_id;
};

struct IMAPSearchInfo
{
    int id;
    int index;
    int length;
};

class ImapMime : public snort::MimeSession
{
    using snort::MimeSession::MimeSession;
private:
    void decode_alert() override;
    void reset_state(snort::Flow* ssn) override;
    bool is_end_of_data(snort::Flow* ssn) override;
};

struct IMAPData
{
    int state;
    int state_flags;
    int session_flags;
    uint32_t body_len;
    uint32_t body_read;
    ImapMime* mime_ssn;
};

class ImapFlowData : public snort::FlowData
{
public:
    ImapFlowData();
    ~ImapFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    IMAPData session;
};

#endif

