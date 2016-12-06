//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "util_net.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#include "main/thread.h"
#include "util.h"

/**
 * A inet_ntoa that has 2 static buffers that are changed between
 * subsequent calls
 *
 * @param ip ip in NETWORK BYTE ORDER
 */
char* inet_ntoax(const SfIp* ip)
{
    static THREAD_LOCAL char ip_buf1[INET6_ADDRSTRLEN];
    static THREAD_LOCAL char ip_buf2[INET6_ADDRSTRLEN];
    static THREAD_LOCAL int buf_num = 0;
    int buf_size = INET6_ADDRSTRLEN;
    char* ip_buf;

    if (buf_num)
        ip_buf = ip_buf2;
    else
        ip_buf = ip_buf1;

    buf_num ^= 1;
    ip_buf[0] = 0;

    if (ip)
        SnortSnprintf(ip_buf, buf_size, "%s", ip->ntoa());

    return ip_buf;
}

