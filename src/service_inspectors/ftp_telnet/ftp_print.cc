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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftp_print.h"

#include <cstring>

#include "log/messages.h"
#include "utils/util_cstring.h"

#include "ft_main.h"
#include "ftp_bounce_lookup.h"
#include "ftp_cmd_lookup.h"
#include "ftp_parse.h"
#include "ftpp_return_codes.h"

using namespace snort;

int PrintConfOpt(bool on, const char* Option)
{
    LogMessage("    %s: %s\n", Option, on ? "ON" : "OFF");
    return FTPP_SUCCESS;
}

/*
 * Function: PrintFormatDate(FTP_DATE_FMT *DateFmt)
 *
 * Purpose: Recursively prints the FTP date validation tree
 *
 * Arguments: DateFmt       => pointer to the date format node
 *
 * Returns: None
 *
 */
static void PrintFormatDate(char* buf, FTP_DATE_FMT* DateFmt)
{
    FTP_DATE_FMT* OptChild;

    if (!DateFmt->empty)
        sfsnprintfappend(buf, BUF_SIZE, "%s", DateFmt->format_string);

    if (DateFmt->optional)
    {
        OptChild = DateFmt->optional;
        sfsnprintfappend(buf, BUF_SIZE, "[");
        PrintFormatDate(buf, OptChild);
        sfsnprintfappend(buf, BUF_SIZE, "]");
    }

    if (DateFmt->next_a)
    {
        if (DateFmt->next_b)
            sfsnprintfappend(buf, BUF_SIZE, "{");
        OptChild = DateFmt->next_a;
        PrintFormatDate(buf, OptChild);
        if (DateFmt->next_b)
        {
            sfsnprintfappend(buf, BUF_SIZE, "|");
            OptChild = DateFmt->next_b;
            PrintFormatDate(buf, OptChild);
            sfsnprintfappend(buf, BUF_SIZE, "}");
        }
    }

    if (DateFmt->next)
        PrintFormatDate(buf, DateFmt->next);
}

/*
 * Function: PrintCmdFmt(FTP_PARAM_FMT *CmdFmt)
 *
 * Purpose: Recursively prints the FTP command parameter validation tree
 *
 * Arguments: CmdFmt       => pointer to the parameter validation node
 *
 * Returns: None
 *
 */
static void PrintCmdFmt(char* buf, FTP_PARAM_FMT* CmdFmt)
{
    FTP_PARAM_FMT* OptChild;

    switch (CmdFmt->type)
    {
    case e_int:
        sfsnprintfappend(buf, BUF_SIZE, " %s", F_INT);
        break;
    case e_number:
        sfsnprintfappend(buf, BUF_SIZE, " %s", F_NUMBER);
        break;
    case e_char:
        sfsnprintfappend(buf, BUF_SIZE, " %s 0x%x", F_CHAR,
            CmdFmt->format.chars_allowed);
        break;
    case e_date:
        sfsnprintfappend(buf, BUF_SIZE, " %s", F_DATE);
        PrintFormatDate(buf, CmdFmt->format.date_fmt);
        break;
    case e_literal:
        sfsnprintfappend(buf, BUF_SIZE, " %s %s", F_LITERAL,
            CmdFmt->format.literal);
        break;
    case e_unrestricted:
        sfsnprintfappend(buf, BUF_SIZE, " %s", F_STRING);
        break;
    case e_strformat:
        sfsnprintfappend(buf, BUF_SIZE, " %s", F_STRING_FMT);
        break;
    case e_host_port:
        sfsnprintfappend(buf, BUF_SIZE, " %s", F_HOST_PORT);
        break;
    case e_long_host_port:
        sfsnprintfappend(buf, BUF_SIZE, " %s", F_LONG_HOST_PORT);
        break;
    case e_extd_host_port:
        sfsnprintfappend(buf, BUF_SIZE, " %s", F_EXTD_HOST_PORT);
        break;
    case e_head:
        break;
    default:
        break;
    }

    if (CmdFmt->optional_fmt)
    {
        OptChild = CmdFmt->optional_fmt;
        sfsnprintfappend(buf, BUF_SIZE, "[");
        PrintCmdFmt(buf, OptChild);
        sfsnprintfappend(buf, BUF_SIZE, "]");
    }

    if (CmdFmt->numChoices)
    {
        int i;
        sfsnprintfappend(buf, BUF_SIZE, "{");
        for (i=0; i<CmdFmt->numChoices; i++)
        {
            if (i)
                sfsnprintfappend(buf, BUF_SIZE, "|");
            OptChild = CmdFmt->choices[i];
            PrintCmdFmt(buf, OptChild);
        }
        sfsnprintfappend(buf, BUF_SIZE, "}");
    }

    if (CmdFmt->next_param_fmt && CmdFmt->next_param_fmt->prev_optional)
        PrintCmdFmt(buf, CmdFmt->next_param_fmt);
}

// FIXIT-L orphan code until FTP client inspector acquires a show() method
#if 0
int PrintFTPClientConf(FTP_CLIENT_PROTO_CONF* ClientConf)
{
    FTP_BOUNCE_TO* FTPBounce;
    int iErr;

    LogMessage(FTP_CLIENT_NAME ":\n");

    PrintConfOpt(ClientConf->bounce, "Check for Bounce Attacks");
    PrintConfOpt(ClientConf->telnet_cmds, "Check for Telnet Cmds");
    PrintConfOpt(ClientConf->ignore_telnet_erase_cmds, "Ignore Telnet Cmd Operations");
    LogMessage("    Max Response Length: %d\n", ClientConf->max_resp_len);

    FTPBounce = ftp_bounce_lookup_first(ClientConf->bounce_lookup, &iErr);
    if (FTPBounce)
    {
        LogMessage("    Allow FTP bounces to:\n");

        while (FTPBounce)
        {
            char* addr_str;
            char bits_str[5];
            uint8_t bits;
            bits_str[0] = '\0';

            addr_str = FTPBounce->ip.ntoa();
            bits = (uint8_t)FTPBounce->ip.bits;
            if (((FTPBounce->ip.family == AF_INET) && (bits != 32)) ||
                ((FTPBounce->ip.family == AF_INET6) && (bits != 128)))
            {
                snprintf(bits_str, sizeof(bits_str), "/%hhu", bits);
            }
            if (FTPBounce->porthi)
            {
                LogMessage("        Address: %s%s, Ports: %d-%d\n",
                    addr_str, bits_str[0] ? bits_str : "",
                    FTPBounce->portlo, FTPBounce->porthi);
            }
            else
            {
                LogMessage("        Address: %s%s, Port: %d\n",
                    addr_str, bits_str[0] ? bits_str : "",
                    FTPBounce->portlo);
            }

            FTPBounce = ftp_bounce_lookup_next(ClientConf->bounce_lookup, &iErr);
        }
    }

    return FTPP_SUCCESS;
}
#endif

int PrintFTPServerConf(FTP_SERVER_PROTO_CONF* ServerConf)
{
    int iRet;
    FTP_CMD_CONF* FTPCmd;

    if (!ServerConf)
    {
        return FTPP_INVALID_ARG;
    }

    LogMessage(FTP_SERVER_NAME ":\n");

    PrintConfOpt(ServerConf->telnet_cmds, "Check for Telnet Cmds");
    PrintConfOpt(ServerConf->ignore_telnet_erase_cmds, "Ignore Telnet Cmd Operations");
    LogMessage("    Ignore open data channels: %s\n",
        ServerConf->data_chan ? "YES" : "NO");
    PrintConfOpt(ServerConf->detect_encrypted, "Check for Encrypted Traffic");
    LogMessage("    Continue to check encrypted data: %s\n",
        ServerConf->check_encrypted_data ? "YES" : "NO");

    if (ServerConf->print_commands)
    {
        LogMessage("    FTP Commands:\n");

        FTPCmd = ftp_cmd_lookup_first(ServerConf->cmd_lookup, &iRet);
        while (FTPCmd != nullptr)
        {
            char buf[BUF_SIZE+1];
            snprintf(buf, BUF_SIZE, "        %s { %u ",
                FTPCmd->cmd_name, FTPCmd->max_param_len);

#ifdef PRINT_DEFAULT_CONFIGS
            // FIXIT-L should append, not overwrite
            if (FTPCmd->data_chan_cmd)
                snprintf(buf, BUF_SIZE, "%s", "data_chan ");
            if (FTPCmd->data_xfer_cmd)
                snprintf(buf, BUF_SIZE, "%s", "data_xfer ");
            if (FTPCmd->encr_cmd)
                snprintf(buf, BUF_SIZE, "%s", "encr ");
#endif

            if (FTPCmd->check_validity)
            {
                FTP_PARAM_FMT* CmdFmt = FTPCmd->param_format;
                while (CmdFmt != nullptr)
                {
                    PrintCmdFmt(buf, CmdFmt);

                    CmdFmt = CmdFmt->next_param_fmt;
                }
            }
            LogMessage("%s}\n", buf);
            FTPCmd = ftp_cmd_lookup_next(ServerConf->cmd_lookup, &iRet);
        }
    }

    return FTPP_SUCCESS;
}

