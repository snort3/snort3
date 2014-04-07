/*
 * ftpp_eo_log.h
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
 * Defines the functions for logging within the FTP Telnet preprocessor.
 *
 * NOTES:
 * - 20.09.04:  Initial Development.  SAS
 *
 */
#ifndef FTPP_EO_LOG_H
#define FTPP_EO_LOG_H

#include "ftpp_include.h"
#include "ftpp_si.h"
#include "ftpp_return_codes.h"

void ftpp_eo_event_log_init(void);

int telnet_eo_event_log(TELNET_SESSION *session, int iEvent, void *data,
        void (*free_data)(void *));

int ftp_eo_event_log(FTP_SESSION *session, int iEvent, void *data,
        void (*free_data)(void *));

#endif
