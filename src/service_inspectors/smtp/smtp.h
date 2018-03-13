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

// smtp.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef SMTP_H
#define SMTP_H

// Implementation header with definitions, datatypes and flowdata class for
// SMTP service inspector.

#include "flow/flow.h"
#include "smtp_config.h"

// Direction packet is coming from, if we can figure it out
#define SMTP_PKT_FROM_UNKNOWN  0
#define SMTP_PKT_FROM_CLIENT   1
#define SMTP_PKT_FROM_SERVER   2

// Inspection type
#define SMTP_STATELESS  0
#define SMTP_STATEFUL   1

#define SEARCH_CMD       0
#define SEARCH_RESP      1
#define SEARCH_HDR       2
#define SEARCH_DATA_END  3
#define NUM_SEARCHES  4

#define BOUNDARY     0

#define STATE_CONNECT          0
#define STATE_COMMAND          1    // Command state of SMTP transaction
#define STATE_DATA             2    // Data state
#define STATE_BDATA            3    // Binary data state
#define STATE_TLS_CLIENT_PEND  4    // Got STARTTLS
#define STATE_TLS_SERVER_PEND  5    // Got STARTTLS
#define STATE_TLS_DATA         6    // Successful handshake, TLS encrypted data 
#define STATE_AUTH             7
#define STATE_XEXCH50          8
#define STATE_UNKNOWN          9

#define STATE_DATA_INIT    0
#define STATE_DATA_HEADER  1    // Data header section of data state
#define STATE_DATA_BODY    2    // Data body section of data state
#define STATE_MIME_HEADER  3    // MIME header section within data section
#define STATE_DATA_UNKNOWN 4

// state flags
#define SMTP_FLAG_GOT_MAIL_CMD               0x00000001
#define SMTP_FLAG_GOT_RCPT_CMD               0x00000002
#define SMTP_FLAG_BDAT                       0x00001000
#define SMTP_FLAG_ABORT                      0x00002000

// session flags
#define SMTP_FLAG_XLINK2STATE_GOTFIRSTCHUNK  0x00000001
#define SMTP_FLAG_XLINK2STATE_ALERTED        0x00000002
#define SMTP_FLAG_NEXT_STATE_UNKNOWN         0x00000004
#define SMTP_FLAG_GOT_NON_REBUILT            0x00000008
#define SMTP_FLAG_CHECK_SSL                  0x00000010

#define SMTP_SSL_ERROR_FLAGS \
    (SSL_BOGUS_HS_DIR_FLAG | \
    SSL_BAD_VER_FLAG | \
    SSL_BAD_TYPE_FLAG | \
    SSL_UNKNOWN_FLAG)

#define MAX_AUTH_NAME_LEN  20  // Max length of SASL mechanisms, defined in RFC 4422

enum SMTPRespEnum
{
    RESP_220 = 0,
    RESP_221,
    RESP_235,
    RESP_250,
    RESP_334,
    RESP_354,
    RESP_421,
    RESP_450,
    RESP_451,
    RESP_452,
    RESP_500,
    RESP_501,
    RESP_502,
    RESP_503,
    RESP_504,
    RESP_535,
    RESP_550,
    RESP_551,
    RESP_552,
    RESP_553,
    RESP_554,
    RESP_LAST
};

enum SMTPHdrEnum
{
    HDR_CONTENT_TYPE = 0,
    HDR_CONT_TRANS_ENC,
    HDR_CONT_DISP,
    HDR_LAST
};

enum SMTPDataEndEnum
{
    DATA_END_1 = 0,
    DATA_END_2,
    DATA_END_3,
    DATA_END_4,
    DATA_END_LAST
};

struct SMTPSearchInfo
{
    int id;
    int index;
    int length;
};

struct SMTPAuthName
{
    int length;
    char name[MAX_AUTH_NAME_LEN];
};

class SmtpMime : public snort::MimeSession
{
public:
    using snort::MimeSession::MimeSession;
    SMTP_PROTO_CONF* config;
private:
    int handle_header_line(const uint8_t* ptr, const uint8_t* eol,
        int max_header_len) override;
    int normalize_data(const uint8_t* ptr, const uint8_t* data_end) override;
    void decode_alert() override;
    void reset_state(snort::Flow* ssn) override;
    bool is_end_of_data(snort::Flow* ssn) override;
};

struct SMTPData
{
    int state;
    int state_flags;
    int session_flags;
    uint32_t dat_chunk;
    SmtpMime* mime_ssn;
    SMTPAuthName* auth_name;
};

class SmtpFlowData : public snort::FlowData
{
public:
    SmtpFlowData();
    ~SmtpFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    SMTPData session;
};

extern THREAD_LOCAL bool smtp_normalizing;

#endif
