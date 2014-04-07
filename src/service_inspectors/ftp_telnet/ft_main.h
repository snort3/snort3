/*
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Description:
 *
 * This file defines the publicly available functions for the FTPTelnet
 * functionality for Snort.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#ifndef FT_MAIN_H
#define FT_MAIN_H

#include "ftpp_ui_config.h"
#include "decode.h"

/*
 * The definition of the configuration separators in the snort.conf
 * configure line.
 */
#define CONF_SEPARATORS " \t\n\r"

/*
 * These are the definitions of the parser section delimiting
 * keywords to configure FtpTelnet.  When one of these keywords
 * are seen, we begin a new section.
 */
#define GLOBAL        "global"
#define TELNET        "telnet"
#define FTP           "ftp"
//#define GLOBAL_CLIENT "global_client"
#define CLIENT        "client"
#define SERVER        "server"

extern int16_t ftp_app_id;
extern int16_t ftp_data_app_id;
extern int16_t telnet_app_id;

extern THREAD_LOCAL FTPTELNET_GLOBAL_CONF* ftp_telnet_config;  // FIXIT eliminate

extern THREAD_LOCAL PreprocStats ftpPerfStats;
extern THREAD_LOCAL PreprocStats telnetPerfStats;

void FTPTelnetFreeConfig(FTPTELNET_GLOBAL_CONF *GlobalConf);
int SnortFTPTelnet(FTPTELNET_GLOBAL_CONF*, Packet *p);
int SnortFTPData(Packet *p);
int FTPConfigCheck(SnortConfig*);
int FtpTelnetInitGlobalConfig(FTPTELNET_GLOBAL_CONF *, char *, int);
char *NextToken(const char *delimiters);

int FTPPBounceInit(SnortConfig* sc, char *name, char *parameters, void **dataPtr);
int FTPPBounceEval(Packet*, const uint8_t **cursor, void *dataPtr);

void FTPTelnetCleanupFTPServerConf(void *serverConf);
void FTPTelnetCleanupFTPCMDConf(void *ftpCmd);
void FTPTelnetCleanupFTPClientConf(void *clientConf);
void FTPTelnetCleanupFTPBounceTo(void *ftpBounce);
int FTPTelnetCheckFTPServerConfigs(SnortConfig*, FTPTELNET_GLOBAL_CONF *);
int ProcessFTPGlobalConf(FTPTELNET_GLOBAL_CONF *, char *, int);
int ProcessTelnetConf(FTPTELNET_GLOBAL_CONF *, char *, int);
int ProcessFTPClientConf(FTPTELNET_GLOBAL_CONF *, char *, int);
int ProcessFTPServerConf(FTPTELNET_GLOBAL_CONF *, char *, int);
int PrintFTPGlobalConf(FTPTELNET_GLOBAL_CONF *);
int FTPTelnetCheckConfigs(SnortConfig*, void* );
void FtpTelnetConfig(SnortConfig*, FTPTELNET_GLOBAL_CONF*, char* args);
void PrintFtpTelnetConfig(FTPTELNET_GLOBAL_CONF*);

#endif
