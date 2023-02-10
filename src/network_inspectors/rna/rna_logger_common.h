//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef RNA_LOGGER_COMMON_H
#define RNA_LOGGER_COMMON_H

// Common definitions between rna logger and pnd modules
#define RNA_EVENT_NEW       1000
    #define NEW_HOST            1
    #define NEW_TCP_SERVICE     2
    #define NEW_NET_PROTOCOL    3
    #define NEW_XPORT_PROTOCOL  4
    #define NEW_UDP_SERVICE     6
    #define NEW_CLIENT_APP      7
    #define NEW_OS              8

#define RNA_EVENT_CHANGE    1001
    #define CHANGE_HOPS                 5
    #define CHANGE_TCP_SERVICE_INFO     6
    #define CHANGE_UDP_SERVICE_INFO    10
    #define CHANGE_MAC_INFO            13
    #define CHANGE_MAC_ADD             14
    #define CHANGE_HOST_UPDATE         15
    #define CHANGE_HOST_TYPE           16
    #define CHANGE_VLAN_TAG            18
    #define CHANGE_NETBIOS_NAME        21
    #define CHANGE_BANNER_UPDATE       24
    #define CHANGE_CLIENT_APP_UPDATE   32
    #define CHANGE_FULL_DHCP_INFO      33

#define RUA_EVENT         1004
    #define CHANGE_USER_LOGIN    2
    #define FAILED_USER_LOGIN    5

#endif
