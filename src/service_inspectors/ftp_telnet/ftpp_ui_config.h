/*
 * ftpp_ui_config.h
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 * Kevin Liu <kliu@sourcefire.com>
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
 * This file contains the internal configuration structures
 * for FTPTelnet.
 *
 * This file holds the configuration constructs for the FTPTelnet global
 * configuration and the FTP client configurations.  It also contains the
 * function prototypes for accessing client configurations.
 *
 * NOTES:
 * - 20.09.04:  Initial Development.  SAS
 */

#ifndef FTPP_UI_CONFIG_H
#define FTPP_UI_CONFIG_H

//#include "decode.h"

#include "ftpp_include.h"
#include "hi_util_kmap.h"
#include "ipv6_port.h"
#include "sfrt/sfrt.h"
#include "snort_bounds.h"

/*
 * Defines
 */
#define FTPP_UI_CONFIG_STATELESS 0
#define FTPP_UI_CONFIG_STATEFUL  1

#define FTPP_UI_CONFIG_TELNET_DEF_AYT_THRESHOLD -1
#define FTPP_UI_CONFIG_FTP_DEF_RESP_MSG_MAX -1
#define FTPP_UI_CONFIG_FTP_DEF_CMD_PARAM_MAX 100

#define MIN_CMD 3
#define MAX_CMD 4

typedef KMAP BOUNCE_LOOKUP;

/*
 * Defines a search type for the FTP commands in the client
 * global configuration.  We want this generic so we can change
 * it easily if we change the search type.
 */
typedef KMAP CMD_LOOKUP;

typedef struct s_FTPTELNET_CONF_OPT
{

    int on;     /*< if true, configuration option is on */

}  FTPTELNET_CONF_OPT;

typedef enum s_FTP_PARAM_TYPE
{
    e_head = 0,
    e_unrestricted,   /* The default */
    e_strformat,
    e_int,
    e_number,
    e_char,
    e_date,
    e_literal,
    e_host_port,
    e_long_host_port,
    e_extd_host_port
}  FTP_PARAM_TYPE;

/*
 * Some FTP servers accept MDTM commands to set the modification time
 * on a file.  The most common are servers accept a format using
 * YYYYMMDDHHmmss[.uuu], while others accept a format using
 * YYYYMMDDHHmmss[+|-]TZ format.  Because of this, the default syntax
 * below is for the first case (time format as specified in
 * http://www.ietf.org/internet-drafts/draft-ietf-ftpext-mlst-16.txt)
 *
 * If you need to check validity for a server that uses the TZ format,
 * use the following:
 *
 * cmd_validity MDTM < [ date nnnnnnnnnnnnnn[{+|-}n[n]] ] string >
 *
 * Format uses the following:
 *  n = digit
 *  C = character
 *  . = period (literal)
 *  + = plus (literal)
 *  - = minus (literal)
 *  [ = optional begin
 *  ] = optional end
 *  { = OR begin
 *  } = OR end
 *  | = OR separator
 *
 *  ie, nnnnnnnnnnnnnn[.n[n[n]]]  -->
 *  force conformance to YYYYMMDDHHmmss.uuu,
 *  where 1,2, or 3 microsec digits are optional.
 *
 *  ie, nnnnnnnnnnnnnn[{+|-}n[n]] -->
 *  force conformance to YYYYMMDDHHmmss+TZ,
 *  where optional +TZ is + or - one or two digit number
 */
typedef struct s_FTP_DATE_FMT
{
    char *format_string;
    int empty;
    struct s_FTP_DATE_FMT *next;
    struct s_FTP_DATE_FMT *prev;
    struct s_FTP_DATE_FMT *optional;
    struct s_FTP_DATE_FMT *next_a;
    struct s_FTP_DATE_FMT *next_b;

} FTP_DATE_FMT;

typedef struct s_FTP_PARAM_FMT
{
    FTP_PARAM_TYPE type;
    int optional;

    /* Format is only used for types listed below to specify
     * allowable values.  Other types provide no variances
     * for the format.
     */
    union u_FORMAT
    {
        uint32_t chars_allowed;     /* For type == e_char */
        FTP_DATE_FMT *date_fmt;      /* For type == e_date */
        char* literal;               /* For type == e_literal */
    } format;

    struct s_FTP_PARAM_FMT *prev_param_fmt;
    struct s_FTP_PARAM_FMT *next_param_fmt;
    struct s_FTP_PARAM_FMT *optional_fmt;
    struct s_FTP_PARAM_FMT **choices;
    int numChoices;
    int prev_optional; /* Only set if optional is set */
    const char *next_param; /* Pointer to buffer for the next parameter.
                         To be used to backtrack for optional
                         parameters that don't match. */

}  FTP_PARAM_FMT;

typedef struct s_FTP_CMD_CONF
{
    /* Maximum length for parameters for this cmd.
     * Default -1 is unlimited */
    unsigned int  max_param_len;
    int  max_param_len_overridden;

    int  check_validity;
    int  data_chan_cmd;
    int  data_xfer_cmd;
    int  file_put_cmd;
    int  file_get_cmd;
    int  encr_cmd;
    int  login_cmd;
    int  dir_response;

    FTP_PARAM_FMT *param_format;
    char cmd_name[1];  // variable length array

}  FTP_CMD_CONF;

typedef struct s_PROTO_CONF
{
    unsigned int port_count;
    char ports[MAXPORTS];
}  PROTO_CONF;

/*
 * This is the configuration construct that holds the specific
 * options for a FTP server.  Each unique server has it's own
 * structure and there is a global structure for servers that
 * don't have a unique configuration.
 */
struct FTP_SERVER_PROTO_CONF
{
    /* Ports must be first */
    PROTO_CONF proto_ports;
    char *serverAddr;

    unsigned int def_max_param_len;
    unsigned int max_cmd_len;

    int print_commands;
    int data_chan;
    int check_encrypted_data;

    CMD_LOOKUP    *cmd_lookup;

    FTPTELNET_CONF_OPT telnet_cmds;
    FTPTELNET_CONF_OPT ignore_telnet_erase_cmds;
    FTPTELNET_CONF_OPT detect_encrypted;
};

typedef struct s_FTP_BOUNCE_TO
{
    snort_ip ip;
    int relevant_bits;
    unsigned short portlo;
    unsigned short porthi;
} FTP_BOUNCE_TO;

/*
 * This is the configuration construct that holds the specific
 * options for a FTP client.  Each unique client has it's own
 * structure and there is a global structure for clients that
 * don't have a unique configuration.
 */
struct FTP_CLIENT_PROTO_CONF
{
    char *clientAddr;
    unsigned int  max_resp_len;
    int data_chan;

    FTPTELNET_CONF_OPT bounce;
    FTPTELNET_CONF_OPT telnet_cmds;
    FTPTELNET_CONF_OPT ignore_telnet_erase_cmds;

    /* allow_bounce to IP/mask port|port-range */
    /* TODO: change this to use a quick find of IP/mask */
    BOUNCE_LOOKUP    *bounce_lookup;
};

/*
 * This is the configuration construct that holds the specific
 * options for telnet.  There is a global structure for all telnet
 * connections.
 */
typedef struct s_TELNET_PROTO_CONF
{
    /* Ports must be first */
    PROTO_CONF proto_ports;

    int normalize;
    int ayt_threshold;
    int check_encrypted_data;

    FTPTELNET_CONF_OPT detect_encrypted;

    char detect_anomalies;

}  TELNET_PROTO_CONF;

/*
 * This is the configuration for the global FTPTelnet
 * configuration.  It contains the global aspects of the
 * configuration, a standard global default configuration,
 * and client configurations.
 */
struct FTPTELNET_GLOBAL_CONF
{
    FTP_CLIENT_PROTO_CONF* ftp_client;
    FTP_SERVER_PROTO_CONF* ftp_server;
    TELNET_PROTO_CONF* telnet_config;
};

/*
 * Functions
 */
int ftpp_ui_config_init_global_conf(FTPTELNET_GLOBAL_CONF *GlobalConf);
int ftpp_ui_config_default(FTPTELNET_GLOBAL_CONF *GlobalConf);
int ftpp_ui_config_reset_global(FTPTELNET_GLOBAL_CONF *GlobalConf);
int ftpp_ui_config_reset_ftp_client(FTP_CLIENT_PROTO_CONF *ClientConf,
                                    char first);
int ftpp_ui_config_reset_ftp_server(FTP_SERVER_PROTO_CONF *ServerConf,
                                    char first);
void ftpp_ui_config_reset_ftp_cmd_format(FTP_PARAM_FMT *ThisFmt);
void ftpp_ui_config_reset_ftp_cmd_date_format(FTP_DATE_FMT *DateFmt);
int ftpp_ui_config_reset_ftp_cmd(FTP_CMD_CONF *FTPCmd);
int ftpp_ui_config_reset_telnet_proto(TELNET_PROTO_CONF *ClientConf);

#endif

