/*--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
*/
/* daq_socket.h author Russ Combs <rucombs@cisco.com> */
/* this is a C include, not C++ */

#ifndef DAQ_AUX_H
#define DAQ_AUX_H

#include <stdint.h>

/* for socket / proxy connections handling payload only */
#define DLT_SOCKET 230

#define DAQ_SKT_FLAG_TO_SERVER  0x01
#define DAQ_SKT_FLAG_START_FLOW 0x02
#define DAQ_SKT_FLAG_END_FLOW   0x04

/* socket DAQ sets priv_ptr to this */
typedef struct
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t ip_proto;
    uint8_t flags;
} DAQ_SktHdr_t;

#endif

