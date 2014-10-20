/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef KEYWORDS_H
#define KEYWORDS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define DEFAULT_LARGE_RULE_GROUP 9
#define MAX_RULE_COUNT (65535 * 2)

#define RULE_PROTO_OPT__IP    "ip"
#define RULE_PROTO_OPT__TCP   "tcp"
#define RULE_PROTO_OPT__UDP   "udp"
#define RULE_PROTO_OPT__ICMP  "icmp"

#define RULE_DIR_OPT__DIRECTIONAL    "->"
#define RULE_DIR_OPT__BIDIRECTIONAL  "<>"

#define CHECKSUM_MODE_OPT__ALL      "all"
#define CHECKSUM_MODE_OPT__NONE     "none"
#define CHECKSUM_MODE_OPT__IP       "ip"
#define CHECKSUM_MODE_OPT__NO_IP    "noip"
#define CHECKSUM_MODE_OPT__TCP      "tcp"
#define CHECKSUM_MODE_OPT__NO_TCP   "notcp"
#define CHECKSUM_MODE_OPT__UDP      "udp"
#define CHECKSUM_MODE_OPT__NO_UDP   "noudp"
#define CHECKSUM_MODE_OPT__ICMP     "icmp"
#define CHECKSUM_MODE_OPT__NO_ICMP  "noicmp"

#endif
