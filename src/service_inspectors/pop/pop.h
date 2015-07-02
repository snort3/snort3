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
 * pop.h: Definitions, structs, function prototype(s) for
 *		the POP service inspectors.
 * Author: Bhagyashree Bantwal <bbantwal@cisco.com>
 */

#ifndef POP_H
#define POP_H

#include "protocols/packet.h"
#include "stream/stream_api.h"
#include "profiler.h"
#include "pop_config.h"
/* Direction packet is coming from, if we can figure it out */
#define POP_PKT_FROM_UNKNOWN  0
#define POP_PKT_FROM_CLIENT   1
#define POP_PKT_FROM_SERVER   2

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
#define POP_FLAG_NEXT_STATE_UNKNOWN         0x00000004
#define POP_FLAG_GOT_NON_REBUILT            0x00000008
#define POP_FLAG_CHECK_SSL                  0x00000010

/* Maximum length of header chars before colon, based on Exim 4.32 exploit */
#define MAX_HEADER_NAME_LEN 64
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

struct POPCmdConfig
{
    char alert;                  /*  1 if alert when seen                          */
    char normalize;              /*  1 if we should normalize this command         */
    int max_line_len;            /*  Max length of this particular command         */
};

struct POPSearchInfo
{
    int id;
    int index;
    int length;
};

struct POPData
{
    int state;
    int prev_response;
    int state_flags;
    int session_flags;
    MimeState mime_ssn;
};

class PopFlowData : public FlowData
{
public:
    PopFlowData();
    ~PopFlowData();

    static void init()
    { flow_id = FlowData::get_flow_id(); }

public:
    static unsigned flow_id;
    POPData session;
};

#endif

