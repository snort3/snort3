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

// ftp_client.h author Steven A. Sturges <ssturges@sourcefire.com>

// contributors:
// Daniel J. Roelker <droelker@sourcefire.com>
// Marc A. Norton <mnorton@sourcefire.com>

#ifndef FTP_CLIENT_H
#define FTP_CLIENT_H

/*
 * FTP Client Module
 *
 * This file defines the client reqest structure and functions
 * to access client inspection.
 */

struct FTP_CLIENT_REQ
{
    const char* cmd_line;
    unsigned int cmd_line_size;

    const char* cmd_begin;
    const char* cmd_end;
    unsigned int cmd_size;

    const char* param_begin;
    const char* param_end;
    unsigned int param_size;

    const char* pipeline_req;
};

struct FTP_CLIENT
{
    FTP_CLIENT_REQ request;
    int (* state)(void*, unsigned char, int);
};

int ftp_client_inspection(void* session, unsigned char* data, int dsize);

#endif

