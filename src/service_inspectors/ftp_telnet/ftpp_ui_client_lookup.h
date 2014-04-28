/*
 * ftpp_ui_client_lookup.h
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
 * This file contains function definitions for client lookups.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#ifndef FTPP_UI_CLIENT_LOOKUP_H
#define FTPP_UI_CLIENT_LOOKUP_H

#include "ftpp_include.h"
#include "ftpp_ui_config.h"

int ftpp_ui_client_lookup_init(CLIENT_LOOKUP **ClientLookup);
int ftpp_ui_client_lookup_cleanup(CLIENT_LOOKUP **ClientLookup);
int ftpp_ui_client_lookup_add(CLIENT_LOOKUP *ClientLookup, sfip_t * IP,
                            FTP_CLIENT_PROTO_CONF *ClientConf);

FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_find(CLIENT_LOOKUP *ClientLookup, 
                                            snort_ip_p Ip, int *iError);
FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_first(CLIENT_LOOKUP *ClientLookup,
                                            int *iError);
FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_next(CLIENT_LOOKUP *ClientLookup,
                                           int *iError);

#endif
