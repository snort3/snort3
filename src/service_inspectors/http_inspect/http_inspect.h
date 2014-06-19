/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
 ****************************************************************************/

#ifndef HTTP_INSPECT_H
#define HTTP_INSPECT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

struct BaseApi;

extern const BaseApi* ips_http_uri;
extern const BaseApi* ips_http_header;
extern const BaseApi* ips_http_client_body;
extern const BaseApi* ips_http_method;
extern const BaseApi* ips_http_cookie;
extern const BaseApi* ips_http_stat_code;
extern const BaseApi* ips_http_stat_msg;
extern const BaseApi* ips_http_raw_uri;
extern const BaseApi* ips_http_raw_header;
extern const BaseApi* ips_http_raw_cookie;

#endif

