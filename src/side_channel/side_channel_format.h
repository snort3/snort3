//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SIDE_CHANNEL_FORMAT_H
#define SIDE_CHANNEL_FORMAT_H

#include <string>

#include "framework/connector.h"
#include "side_channel/side_channel.h"

#define TXT_UNIT_LEN                3

std::string sc_msg_hdr_to_text(const SCMsgHdr* hdr);
std::string sc_msg_data_to_text(const uint8_t* data, uint32_t length);
snort::ConnectorMsg from_text(const char* str_ptr, uint32_t size);

#endif
