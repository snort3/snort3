//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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
/*
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 */

#ifndef FTP_PARSE_H
#define FTP_PARSE_H

#include "ftpp_ui_config.h"

/*
 * These are the definitions of the parser section delimiting
 * keywords to configure FtpTelnet.  When one of these keywords
 * are seen, we begin a new section.
 */
#define TELNET        "telnet"
#define FTP           "ftp"
#define CLIENT        "client"
#define SERVER        "server"

/*
 * Data type keywords
 */
#define START_CMD_FORMAT    "<"
#define END_CMD_FORMAT      ">"
#define F_INT               "int"
#define F_NUMBER            "number"
#define F_CHAR              "char"
#define F_DATE              "date"
#define F_LITERAL           "'"
#define F_STRING            "string"
#define F_STRING_FMT        "formatted_string"
#define F_HOST_PORT         "host_port"
#define F_LONG_HOST_PORT    "long_host_port"
#define F_EXTD_HOST_PORT    "extd_host_port"

int ProcessFTPCmdValidity(
    FTP_SERVER_PROTO_CONF* ServerConf,
    const char* cmd, const char* fmt,
    char* ErrorString, int ErrStrLen);

int ProcessFTPAllowBounce(
    FTP_CLIENT_PROTO_CONF* ClientConf, const uint8_t* addr, unsigned len,
    Port low, Port high);

#endif

