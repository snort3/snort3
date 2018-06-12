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

#ifndef SMTP_CONFIG_H
#define SMTP_CONFIG_H

// Configuration for SMTP inspector

#include "mime/file_mime_process.h"
#include "search_engines/search_tool.h"

enum NORM_TYPES
{
    NORMALIZE_NONE = 0,
    NORMALIZE_CMDS,
    NORMALIZE_ALL
};

enum XLINK2STATE
{
    DISABLE_XLINK2STATE = 0,
    ALERT_XLINK2STATE,
    DROP_XLINK2STATE
};

enum SMTPCmdEnum
{
    CMD_ATRN = 0,
    CMD_AUTH,
    CMD_BDAT,
    CMD_DATA,
    CMD_DEBUG,
    CMD_EHLO,
    CMD_EMAL,
    CMD_ESAM,
    CMD_ESND,
    CMD_ESOM,
    CMD_ETRN,
    CMD_EVFY,
    CMD_EXPN,
    CMD_HELO,
    CMD_HELP,
    CMD_IDENT,
    CMD_MAIL,
    CMD_NOOP,
    CMD_ONEX,
    CMD_QUEU,
    CMD_QUIT,
    CMD_RCPT,
    CMD_RSET,
    CMD_SAML,
    CMD_SEND,
    CMD_SIZE,
    CMD_STARTTLS,
    CMD_SOML,
    CMD_TICK,
    CMD_TIME,
    CMD_TURN,
    CMD_TURNME,
    CMD_VERB,
    CMD_VRFY,
    CMD_X_EXPS,
    CMD_XADR,
    CMD_XAUTH,
    CMD_XCIR,
    CMD_XEXCH50,
    CMD_XGEN,
    CMD_XLICENSE,
    CMD_X_LINK2STATE,
    CMD_XQUE,
    CMD_XSTA,
    CMD_XTRN,
    CMD_XUSR,
    CMD_ABORT,
    CMD_LAST
};

enum SMTPCmdTypeEnum
{
    SMTP_CMD_TYPE_NORMAL = 0,
    SMTP_CMD_TYPE_DATA,
    SMTP_CMD_TYPE_BDATA,
    SMTP_CMD_TYPE_AUTH,
    SMTP_CMD_TYPE_LAST
};

struct SMTPCmdConfig
{
    bool alert;
    bool normalize;     //  1 if we should normalize this command 
    int max_line_len;   //  Max length of this particular command
};

struct SMTPSearch
{
    const char* name;
    int name_len;
};

struct SMTPToken
{
    const char* name;
    int name_len;
    int search_id;
    SMTPCmdTypeEnum type;
};

struct SMTP_PROTO_CONF
{
    NORM_TYPES normalize;
    bool ignore_tls_data;
    int max_auth_command_line_len = 1000;
    int max_command_line_len = 0;
    int max_header_line_len = 0;
    int max_response_line_len = 0;
    int xlink2state;
    MailLogConfig log_config;
    snort::DecodeConfig decode_conf;

    uint32_t xtra_filename_id;
    uint32_t xtra_mfrom_id;
    uint32_t xtra_rcptto_id;
    uint32_t xtra_ehdrs_id;

    int num_cmds;
    SMTPToken* cmds;
    SMTPCmdConfig* cmd_config;
    SMTPSearch* cmd_search;
    snort::SearchTool* cmd_search_mpse;
};

struct SmtpStats
{
    PegCount packets;
    PegCount sessions;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
    MimeStats mime_stats;
};

extern const PegInfo smtp_peg_names[];
extern THREAD_LOCAL SmtpStats smtpstats;

#endif
