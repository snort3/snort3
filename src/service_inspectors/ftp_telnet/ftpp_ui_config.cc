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
 * Description:
 *
 * This file contains library calls to configure FTPTelnet.
 *
 * This file deals with configuring FTPTelnet processing.  It contains
 * routines to set a default configuration, add client configurations, etc.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftpp_ui_config.h"

#include "utils/util.h"

#include "ftp_bounce_lookup.h"
#include "ftp_cmd_lookup.h"
#include "ftpp_return_codes.h"

FTP_CLIENT_PROTO_CONF::FTP_CLIENT_PROTO_CONF()
{
    ftp_bounce_lookup_init(&bounce_lookup);
}

FTP_CLIENT_PROTO_CONF::~FTP_CLIENT_PROTO_CONF()
{
    ftp_bounce_lookup_cleanup(&bounce_lookup);
}

FTP_SERVER_PROTO_CONF::FTP_SERVER_PROTO_CONF()
{
    ftp_cmd_lookup_init(&cmd_lookup);

    def_max_param_len = FTPP_UI_CONFIG_FTP_DEF_CMD_PARAM_MAX;
    max_cmd_len = MAX_CMD;

    print_commands = data_chan = check_encrypted_data = false;
    telnet_cmds = ignore_telnet_erase_cmds = detect_encrypted = false;
}

FTP_SERVER_PROTO_CONF::~FTP_SERVER_PROTO_CONF()
{
    ftp_cmd_lookup_cleanup(&cmd_lookup);
}

TELNET_PROTO_CONF::TELNET_PROTO_CONF()
{
    normalize = check_encrypted_data = false;
    ayt_threshold = FTPP_UI_CONFIG_TELNET_DEF_AYT_THRESHOLD;
    detect_encrypted = false;
}

/*
 * Function: ftpp_ui_config_reset_ftp_cmd_date_format(FTP_DATE_FMT *DateFmt)
 *
 * Purpose: This function resets an FTP date parameter construct.
 *
 * Arguments: ThisFmt   => pointer to the FTP_DATE_FMT structure
 *
 * Returns: void
 *
 */
void ftpp_ui_config_reset_ftp_cmd_date_format(FTP_DATE_FMT* DateFmt)
{
    if (DateFmt->optional)
    {
        ftpp_ui_config_reset_ftp_cmd_date_format(DateFmt->optional);
    }

    if (DateFmt->next)
    {
        ftpp_ui_config_reset_ftp_cmd_date_format(DateFmt->next);
    }

    if (DateFmt->format_string)
    {
        snort_free(DateFmt->format_string);
    }
    snort_free(DateFmt);
}

/*
 * Function: ftpp_ui_config_reset_ftp_cmd_format(FTP_PARAM_FMT *ThisFmt)
 *
 * Purpose: This function resets an FTP parameter construct.
 *
 * Arguments: ThisFmt   => pointer to the FTP_PARAM_FMT structure
 *
 * Returns: void
 *
 */
void ftpp_ui_config_reset_ftp_cmd_format(FTP_PARAM_FMT* ThisFmt)
{
    if (ThisFmt->optional_fmt)
    {
        ftpp_ui_config_reset_ftp_cmd_format(ThisFmt->optional_fmt);
    }
    if (ThisFmt->numChoices)
    {
        int i;
        for (i=0; i<ThisFmt->numChoices; i++)
        {
            ftpp_ui_config_reset_ftp_cmd_format(ThisFmt->choices[i]);
        }
        snort_free(ThisFmt->choices);
    }

    if (ThisFmt->next_param_fmt)
    {
        /* Don't free this one twice if its after an optional */
        FTP_PARAM_FMT* next = ThisFmt->next_param_fmt;
        ThisFmt->next_param_fmt->prev_param_fmt->next_param_fmt = nullptr;
        ThisFmt->next_param_fmt = nullptr;
        ftpp_ui_config_reset_ftp_cmd_format(next);
    }

    if (ThisFmt->type == e_date)
    {
        ftpp_ui_config_reset_ftp_cmd_date_format(ThisFmt->format.date_fmt);
    }
    if (ThisFmt->type == e_literal)
    {
        snort_free(ThisFmt->format.literal);
    }

    snort_free(ThisFmt);
}

/*
 * Function: ftpp_ui_config_reset_ftp_cmd(FTP_CMD_CONF *FTPCmd)
 *
 * Purpose: This function resets a FTP command construct.
 *
 * Arguments: FTPCmd    => pointer to the FTP_CMD_CONF structure
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_config_reset_ftp_cmd(FTP_CMD_CONF* FTPCmd)
{
    FTP_PARAM_FMT* NextCmdFormat = FTPCmd->param_format;

    if (NextCmdFormat)
    {
        ftpp_ui_config_reset_ftp_cmd_format(NextCmdFormat);
    }

    return FTPP_SUCCESS;
}

