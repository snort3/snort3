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
 *
 * Description:
 *
 * This file wraps the FTPTelnet functionality for Snort
 * and starts the Normalization & Protocol checks.
 *
 * The file takes a Packet structure from the Snort IDS to start the
 * FTP/Telnet Normalization & Protocol checks.  It also uses the Stream
 * Interface Module which is also Snort-centric.  Mainly, just a wrapper
 * to FTP/Telnet functionality, but a key part to starting the basic flow.
 *
 * The main bulk of this file is taken up with user configuration and
 * parsing.  The reason this is so large is because FTPTelnet takes
 * very detailed configuration parameters for each specified FTP client,
 * to provide detailed control over an internal network and robust control
 * of the external network.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ft_main.h"

#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "utils/util.h"

#include "ftp_cmd_lookup.h"
#include "ftp_bounce_lookup.h"
#include "ftpp_return_codes.h"

void CleanupFTPCMDConf(void* ftpCmd)
{
    FTP_CMD_CONF* FTPCmd = (FTP_CMD_CONF*)ftpCmd;
    /* Free the FTP_PARAM_FMT stuff... */
    ftpp_ui_config_reset_ftp_cmd(FTPCmd);

    snort_free(FTPCmd);
}

void CleanupFTPServerConf(void* serverConf)
{
    FTP_SERVER_PROTO_CONF* ServerConf = (FTP_SERVER_PROTO_CONF*)serverConf;
    if (ServerConf == nullptr)
        return;

    /* Iterate through each cmd_lookup for this server */
#if 0
    int iRet = FTPP_SUCCESS;
    FTP_CMD_CONF* cmdConf = ftp_cmd_lookup_first(ServerConf->cmd_lookup, &iRet);

    while (cmdConf && (iRet == FTPP_SUCCESS))
    {
        if ( cmdConf->param_format )
        {
            snort_free(cmdConf->param_format);
            cmdConf->param_format = nullptr;
        }
        cmdConf = ftp_cmd_lookup_next(ServerConf->cmd_lookup, &iRet);
    }
#endif
    ftp_cmd_lookup_cleanup(&ServerConf->cmd_lookup);
}

void CleanupFTPBounceTo(void* ftpBounce)
{
    FTP_BOUNCE_TO* FTPBounce = (FTP_BOUNCE_TO*)ftpBounce;
    snort_free(FTPBounce);
}

/*
 * Function: CheckFTPCmdOptions(FTP_SERVER_PROTO_CONF *serverConf)
 *
 * Purpose: This checks that the FTP configuration provided has
 *          options for CMDs that make sense:
 *          -- check if max_len == 0 & there is a cmd_validity
 *
 * Arguments: serverConf    => pointer to Server Configuration
 *
 * Returns: 0               => no errors
 *          1               => errors
 *
 */
static int CheckFTPCmdOptions(FTP_SERVER_PROTO_CONF* serverConf)
{
    FTP_CMD_CONF* cmdConf;
    int iRet =0;
    int config_error = 0;

    cmdConf = ftp_cmd_lookup_first(serverConf->cmd_lookup, &iRet);
    while (cmdConf && (iRet == FTPP_SUCCESS))
    {
        size_t len = strlen(cmdConf->cmd_name);
        if ( len > serverConf->max_cmd_len )
            serverConf->max_cmd_len = len;

        len = cmdConf->max_param_len;
        if ( !len )
            len = serverConf->def_max_param_len;

        if ( cmdConf->check_validity && !len )
        {
            snort::ErrorMessage("FTPConfigCheck() configuration for server, "
                "command '%s' has max length of 0 and parameters to validate\n",
                cmdConf->cmd_name);
            config_error = 1;
        }
        cmdConf = ftp_cmd_lookup_next(serverConf->cmd_lookup, &iRet);
    }

    return config_error;
}

/*
 * Function: CheckFTPServerConfigs()
 *
 * Purpose: This checks that the FTP server configurations are reasonable
 *
 * Arguments: None
 *
 * Returns: -1 on error
 *
 */
int CheckFTPServerConfigs(snort::SnortConfig*, FTP_SERVER_PROTO_CONF* serverConf)
{
    if (CheckFTPCmdOptions(serverConf))
    {
        snort::ErrorMessage("FTPConfigCheck(): invalid configuration for FTP commands\n");
        return -1;
    }
    return 0;
}

// FIXIT-L eliminate legacy void* cruft
int FTPCheckConfigs(snort::SnortConfig* sc, void* pData)
{
    FTP_SERVER_PROTO_CONF* config = (FTP_SERVER_PROTO_CONF*)pData;

    if ( !config )
    {
        snort::ErrorMessage("FTP configuration requires "
            "default client and default server configurations.\n");
        return -1;
    }

    int rval;
    if ((rval = CheckFTPServerConfigs(sc, config)))
        return rval;

    //  Verify that FTP client and FTP data inspectors are initialized.
    if(!snort::InspectorManager::get_inspector(FTP_CLIENT_NAME, false))
    {
        snort::ParseError("ftp_server requires that %s also be configured.", FTP_CLIENT_NAME);
        return -1;
    }

    if(!snort::InspectorManager::get_inspector(FTP_DATA_NAME, false))
    {
        snort::ParseError("ftp_server requires that %s also be configured.", FTP_DATA_NAME);
        return -1;
    }

    return 0;
}

void do_detection(snort::Packet* p)
{
    snort::DataBus::publish(PACKET_EVENT, p);
    snort::DetectionEngine::disable_all(p);
}

