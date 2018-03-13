//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// dnp3_reassembly.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Ryan Jordan

#ifndef DNP3_REASSEMBLY_H
#define DNP3_REASSEMBLY_H

#include "dnp3_module.h"
#include "dnp3.h"

bool dnp3_full_reassembly(dnp3ProtoConf& config, dnp3_session_data_t* session, snort::Packet* p,
    const uint8_t* pdu_start, uint16_t pdu_length);
void dnp3_reassembly_reset(dnp3_reassembly_data_t* rdata);

#endif

