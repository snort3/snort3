/*
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
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2012-2013 Sourcefire, Inc.
 *
 * Author: Michael Altizer <maltizer@sourcefire.com>
 *
 */
#include "sscm_logger.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "side_channel/sidechannel.h"
#include "util.h"

#define CONF_SEPARATORS     " \t\n\r,"
#define CONF_RX_FILE        "rx-log-file"
#define CONF_TX_FILE        "tx-log-file"
#define CONF_PRIMER_FILE    "primer-file"

enum ConfState
{
    STATE_START,
    STATE_RX_FILE,
    STATE_TX_FILE,
    STATE_PRIMER_FILE
};

static char rx_log_file[PATH_MAX];  // FIXIT 1 / process
static int rx_log_fd = -1;
static char tx_log_file[PATH_MAX];
static int tx_log_fd = -1;
static char primer_log_file[PATH_MAX];

static int LoggerRXHandler(SCMsgHdr *hdr, const uint8_t *msg, uint32_t length)
{
    SideChannelWriteMsgToFile(rx_log_fd, hdr, msg, length);
    return 0;
}

static int LoggerTXHandler(SCMsgHdr *hdr, const uint8_t *msg, uint32_t length)
{
    SideChannelWriteMsgToFile(tx_log_fd, hdr, msg, length);
    return 0;
}

static int ConfigLogger(char *args)
{
    char *token;
    char* lasts = "";
    char *argcpy = args;
    enum ConfState confState = STATE_START;

    for (token = strtok_r(argcpy, CONF_SEPARATORS, &lasts);
        token;
        token = strtok_r(NULL, CONF_SEPARATORS, &lasts))
    {
        switch (confState)
        {
            case STATE_START:
                if (strcmp(token, CONF_RX_FILE) == 0)
                    confState = STATE_RX_FILE;
                else if (strcmp(token, CONF_TX_FILE) == 0)
                    confState = STATE_TX_FILE;
                else if (strcmp(token, CONF_PRIMER_FILE) == 0)
                    confState = STATE_PRIMER_FILE;
                else
                    FatalError("Invalid logger side channel configuration token: '%s'\n", token);
                break;
            case STATE_RX_FILE:
                snprintf(rx_log_file, sizeof(rx_log_file), "%s", token);
                confState = STATE_START;
                break;
            case STATE_TX_FILE:
                snprintf(tx_log_file, sizeof(tx_log_file), "%s", token);
                confState = STATE_START;
                break;
            case STATE_PRIMER_FILE:
                snprintf(primer_log_file, sizeof(primer_log_file), "%s", token);
                confState = STATE_START;
                break;
            default:
                break;
        }
    }

    return 0;
}

static int InitLogger(void)
{
    if (rx_log_file[0] != '\0')
    {
        LogMessage("Opening '%s' for side channel RX logging...\n", rx_log_file);
        rx_log_fd = open(rx_log_file, O_WRONLY|O_CREAT|O_TRUNC, 0664);
        if (rx_log_fd == -1)
            FatalError("Could not open Logger SCM RX log file '%s': %s (%d)\n", rx_log_file, get_error(errno), errno);
        SideChannelRegisterRXHandler(SC_MSG_TYPE_ANY, LoggerRXHandler, NULL);
    }
    if (tx_log_file[0] != '\0')
    {
        LogMessage("Opening '%s' for side channel TX logging...\n", tx_log_file);
        tx_log_fd = open(tx_log_file, O_WRONLY|O_CREAT|O_TRUNC, 0664);
        if (tx_log_fd == -1)
            FatalError("Could not open Logger SCM TX log file '%s': %s (%d)\n", tx_log_file, get_error(errno), errno);
        SideChannelRegisterTXHandler(SC_MSG_TYPE_ANY, LoggerTXHandler, NULL);
    }

    return 0;
}

static int PostInitLogger(void)
{
    SCMsgHdr hdr;
    uint32_t length;
    uint8_t *msg;
    unsigned int messages;
    int fd;

    if (primer_log_file[0] != '\0')
    {
        fd = open(primer_log_file, O_RDONLY, 0664);
        if (fd == -1)
            FatalError("Could not open Logger SCM Primer log file '%s': %s (%d)\n", primer_log_file, get_error(errno), errno);
        messages = 0;
        while (SideChannelReadMsgFromFile(fd, &hdr, &msg, &length) == 0)
        {
            if (length == 0)
                msg = NULL;
            SideChannelEnqueueDataRX(&hdr, msg, length, free);
            messages++;
        }
        close(fd);
        LogMessage("Primed the side channel with %u messages from '%s'...\n", messages, primer_log_file);
    }

    return 0;
}

static void ShutdownLogger(void)
{
    if (rx_log_fd != -1)
    {
        close(rx_log_fd);
        rx_log_fd = -1;
        SideChannelUnregisterRXHandler(SC_MSG_TYPE_ANY, LoggerRXHandler);
    }
    if (tx_log_fd)
    {
        close(tx_log_fd);
        tx_log_fd = -1;
        SideChannelUnregisterTXHandler(SC_MSG_TYPE_ANY, LoggerTXHandler);
    }
}

static const SCMFunctionBundle loggerFuncs = {  // FIXIT 1 / process
    ConfigLogger,
    InitLogger,
    PostInitLogger,
    NULL,
    NULL,
    ShutdownLogger
};

int SetupLoggerSCM(void)
{
    RegisterSideChannelModule("logger", &loggerFuncs);
    return 0;
}
