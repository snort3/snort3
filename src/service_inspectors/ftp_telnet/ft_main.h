//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
 * Description:
 *
 * This file defines the publicly available functions for the FTPTelnet
 * functionality for Snort.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 */
#ifndef FT_MAIN_H
#define FT_MAIN_H

#include "ftpp_ui_config.h"

#define BUF_SIZE 1024

struct Packet;
struct ProfileStats;
struct SnortConfig;

extern int16_t ftp_data_app_id;

void do_detection(Packet*);

void CleanupFTPServerConf(void* serverConf);
void CleanupFTPCMDConf(void* ftpCmd);
void CleanupFTPBounceTo(void* ftpBounce);

int CheckFTPServerConfigs(SnortConfig*, FTP_SERVER_PROTO_CONF*);
int FTPCheckConfigs(SnortConfig*, void*);

FTP_CLIENT_PROTO_CONF* get_ftp_client(Packet*);
FTP_SERVER_PROTO_CONF* get_ftp_server(Packet*);

#endif

