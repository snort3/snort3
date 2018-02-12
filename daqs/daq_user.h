/*--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
/* daq_user.h author Russ Combs <rucombs@cisco.com> */
/* this is a C include, not C++ */

#ifndef DAQ_USER_H
#define DAQ_USER_H

#include <stdint.h>

/* for raw payload only */
#define DLT_USER 230

/* in: DAQ_QueryFlow_t.type */
#define DAQ_USR_QUERY_PCI       1000

/* DAQ_UsrHdr_t.flags */
#define DAQ_USR_FLAG_TO_SERVER  0x01
#define DAQ_USR_FLAG_START_FLOW 0x02
#define DAQ_USR_FLAG_END_FLOW   0x04

/* out: DAQ_QueryFlow_t.value */
typedef struct
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t ip_proto;
    uint8_t flags;
} DAQ_UsrHdr_t;

#endif

