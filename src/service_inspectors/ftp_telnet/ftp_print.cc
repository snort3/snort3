//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

void print_conf_client(FTP_CLIENT_PROTO_CONF* config)
{
    ConfigLogger::log_flag("bounce", config->bounce);
    ConfigLogger::log_flag("ignore_telnet_erase_cmds", config->ignore_telnet_erase_cmds);
    ConfigLogger::log_value("max_resp_len", config->max_resp_len);
    ConfigLogger::log_flag("telnet_cmds", config->telnet_cmds);

    int ret;

    for (FTP_BOUNCE_TO* FTPBounce = ftp_bounce_lookup_first(config->bounce_lookup, &ret);
        FTPBounce;
        FTPBounce = ftp_bounce_lookup_next(config->bounce_lookup, &ret))
    {
        char buf[BUF_SIZE + 1] = { '\0' };

        FTPBounce->ip.ntop(buf, BUF_SIZE);

        if (FTPBounce->porthi)
            snprintf(buf, BUF_SIZE, ":%d-%d", FTPBounce->portlo, FTPBounce->porthi);
        else
            snprintf(buf, BUF_SIZE, ":%d", FTPBounce->portlo);

        ConfigLogger::log_list("bounce", buf);
    }
}

void print_conf_server(FTP_SERVER_PROTO_CONF* config)
{
    ConfigLogger::log_flag("check_encrypted", config->detect_encrypted);
    ConfigLogger::log_value("def_max_param_len", config->def_max_param_len);
    ConfigLogger::log_flag("encrypted_traffic", config->check_encrypted_data);
    ConfigLogger::log_flag("ignore_data_chan", config->data_chan);
    ConfigLogger::log_flag("ignore_telnet_erase_cmds", config->ignore_telnet_erase_cmds);
    ConfigLogger::log_flag("telnet_cmds", config->telnet_cmds);
    ConfigLogger::log_flag("print_cmds", config->print_commands);

    if (!config->print_commands)
        return;

    int ret;
    std::string cmds;

    for (FTP_CMD_CONF* ftp_cmd = ftp_cmd_lookup_first(config->cmd_lookup, &ret);
        ftp_cmd;
        ftp_cmd = ftp_cmd_lookup_next(config->cmd_lookup, &ret))
    {
        cmds += ftp_cmd->cmd_name;
        cmds += " ";
    }

    if ( !cmds.empty() )
        cmds.pop_back();
    else
        cmds += "none";

    ConfigLogger::log_list("commands", cmds.c_str());
}
