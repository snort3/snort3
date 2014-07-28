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

#define SNORT_CONF_KEYWORD__FILE     "file"
#define SNORT_CONF_KEYWORD__INCLUDE  "include"

/* Macros *********************************************************************/
#define ENABLE_ALL_RULES    1
#define ENABLE_RULE         1
#define ENABLE_ONE_RULE     0
#define MAX_RULE_OPTIONS     256
#define MAX_LINE_LENGTH    32768
#define MAX_IPLIST_ENTRIES  4096
#define DEFAULT_LARGE_RULE_GROUP 9
#define SF_IPPROTO_UNKNOWN -1
#define MAX_RULE_COUNT (65535 * 2)

#define RULE_PROTO_OPT__IP    "ip"
#define RULE_PROTO_OPT__TCP   "tcp"
#define RULE_PROTO_OPT__UDP   "udp"
#define RULE_PROTO_OPT__ICMP  "icmp"

#define RULE_DIR_OPT__DIRECTIONAL    "->"
#define RULE_DIR_OPT__BIDIRECTIONAL  "<>"

/* For user defined rule type */
#define RULE_TYPE_OPT__TYPE    "type"

/* Rule options
 * Only the basic ones are here.  The detection options and preprocessor
 * detection options define their own */
#define RULE_OPT__CLASSTYPE         "classtype"
#define RULE_OPT__DETECTION_FILTER  "detection_filter"
#define RULE_OPT__GID               "gid"
#define RULE_OPT__MSG               "msg"
#define RULE_OPT__METADATA          "metadata"
#define RULE_OPT__PRIORITY          "priority"
#define RULE_OPT__REFERENCE         "reference"
#define RULE_OPT__REVISION          "rev"
#define RULE_OPT__SID               "sid"
#define RULE_OPT__SOID              "soid"
#define RULE_OPT__TAG               "tag"

/* Metadata rule option keys */
#define METADATA_KEY__OS             "os"
#define METADATA_KEY__RULE_TYPE      "rule-type"
#define METADATA_KEY__SERVICE        "service"

/* Metadata rule option values */
#define METADATA_VALUE__DECODE    "decode"
#define METADATA_VALUE__DETECT    "detect"
#define METADATA_VALUE__DISABLED  "disabled"
#define METADATA_VALUE__ENABLED   "enabled"
#define METADATA_VALUE__OFF       "off"
#define METADATA_VALUE__ON        "on"
#define METADATA_VALUE__MODULE   "preproc"
#define METADATA_VALUE__SHARED    "shared"

/* Tag options */
#define TAG_OPT__BYTES     "bytes"
#define TAG_OPT__DST       "dst"
#define TAG_OPT__HOST      "host"
#define TAG_OPT__PACKETS   "packets"
#define TAG_OPT__SECONDS   "seconds"
#define TAG_OPT__SESSION   "session"
#define TAG_OPT__SRC       "src"

/* Threshold options (for detection_filter) */
#define THRESHOLD_OPT__COUNT    "count"
#define THRESHOLD_OPT__SECONDS  "seconds"
#define THRESHOLD_OPT__TRACK    "track"
#define THRESHOLD_TRACK__BY_DST    "by_dst"
#define THRESHOLD_TRACK__BY_SRC    "by_src"

#define POLICY_MODE_PASSIVE     "tap"
#define POLICY_MODE_INLINE      "inline"
#define POLICY_MODE_INLINE_TEST "inline_test"

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

#define RULE_STATE_OPT__DISABLED   "disabled"
#define RULE_STATE_OPT__ENABLED    "enabled"

#endif

