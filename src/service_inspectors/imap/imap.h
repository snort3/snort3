//--------------------------------------------------------------------------
// Copyright (C) 2015 Cisco and/or its affiliates. All rights reserved.
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

/*
 * imap.h: Definitions, structs, function prototype(s) for
 * Author: Bhagyashree Bantwal <bbantwal@cisco.com>
 */

#ifndef IMAP_H
#define IMAP_H

#include "protocols/packet.h"
#include "stream/stream_api.h"
#include "profiler.h"
#include "imap_config.h"
/* Direction packet is coming from, if we can figure it out */
#define IMAP_PKT_FROM_UNKNOWN  0
#define IMAP_PKT_FROM_CLIENT   1
#define IMAP_PKT_FROM_SERVER   2

#define SEARCH_CMD       0
#define SEARCH_RESP      1
#define SEARCH_HDR       2
#define SEARCH_DATA_END  3
#define NUM_SEARCHES  4

#define BOUNDARY     0

#define STATE_DATA             0    /* Data state */
#define STATE_TLS_CLIENT_PEND  1    /* Got STARTTLS */
#define STATE_TLS_SERVER_PEND  2    /* Got STARTTLS */
#define STATE_TLS_DATA         3    /* Successful handshake, TLS encrypted data */
#define STATE_COMMAND          4
#define STATE_UNKNOWN          5

#define STATE_DATA_INIT    0
#define STATE_DATA_HEADER  1    /* Data header section of data state */
#define STATE_DATA_BODY    2    /* Data body section of data state */
#define STATE_MIME_HEADER  3    /* MIME header section within data section */
#define STATE_DATA_UNKNOWN 4

/* session flags */
#define IMAP_FLAG_NEXT_STATE_UNKNOWN         0x00000004
#define IMAP_FLAG_GOT_NON_REBUILT            0x00000008
#define IMAP_FLAG_CHECK_SSL                  0x00000010

/* Maximum length of header chars before colon, based on Exim 4.32 exploit */
#define MAX_HEADER_NAME_LEN 64
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

struct IMAPCmdConfig
{
    char alert;                  /*  1 if alert when seen                          */
    char normalize;              /*  1 if we should normalize this command         */
    int max_line_len;            /*  Max length of this particular command         */
};

struct IMAPSearchInfo
{
    int id;
    int index;
    int length;
};

struct IMAPData
{
    int state;
    int state_flags;
    int session_flags;
    uint32_t body_len;
    uint32_t body_read;
    MimeState mime_ssn;
};

class ImapFlowData : public FlowData
{
public:
    ImapFlowData();
    ~ImapFlowData();

    static void init()
    { flow_id = FlowData::get_flow_id(); }

public:
    static unsigned flow_id;
    IMAPData session;
};

#endif

