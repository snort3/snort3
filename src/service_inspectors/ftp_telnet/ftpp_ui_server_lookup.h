/*
 * ftpp_ui_server_lookup.h
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 * Steven A. Sturges <ssturges@sourcefire.com>
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
 * This file contains function definitions for server lookups.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#ifndef FTPP_UI_SERVER_LOOKUP_H
#define FTPP_UI_SERVER_LOOKUP_H

#include "ftpp_include.h"
#include "ftpp_ui_config.h"

int ftpp_ui_server_lookup_init(SERVER_LOOKUP **ServerLookup);
int ftpp_ui_server_lookup_cleanup(SERVER_LOOKUP **ServerLookup);
int ftpp_ui_server_lookup_add(SERVER_LOOKUP *ServerLookup, sfip_t *IP,
                            FTP_SERVER_PROTO_CONF *ServerConf);

FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_find(SERVER_LOOKUP *ServerLookup,
                                            snort_ip_p Ip, int *iError);
int ftpp_ui_server_iterate(
    SnortConfig*,SERVER_LOOKUP *ServerLookup,
    sfrt_sc_iterator_callback3 userfunc,
    int *iError
    );

#endif
