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

// ftp_server.h author Steven A. Sturges <ssturges@sourcefire.com>

// contributors:
// Daniel J. Roelker <droelker@sourcefire.com>
// Marc A. Norton <mnorton@sourcefire.com>

#ifndef FTP_SERVER_H
#define FTP_SERVER_H

/*
 * FTP Server Module
 *
 * This file defines the server structure and functions to access server
 * inspection.
 */

typedef struct s_FTP_SERVER_RSP
{
    char* rsp_line;
    unsigned int rsp_line_size;

    char* rsp_begin;
    char* rsp_end;
    unsigned int rsp_size;

    char* msg_begin;
    char* msg_end;
    unsigned int msg_size;

    char* pipeline_req;
    int state;
} FTP_SERVER_RSP;

typedef struct s_FTP_SERVER
{
    FTP_SERVER_RSP response;
} FTP_SERVER;

int ftp_server_inspection(void* S, unsigned char* data, int dsize);

#endif

