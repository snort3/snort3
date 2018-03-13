//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// smtp_util.h authors Andy Mullican and Todd Wease

#ifndef SMTP_UTIL_H
#define SMTP_UTIL_H

// SMTP helper functions

#include "smtp_config.h"

namespace snort
{
struct Packet;
}

void SMTP_GetEOL(const uint8_t*, const uint8_t*, const uint8_t**, const uint8_t**);
void SMTP_LogFuncs(SMTP_PROTO_CONF*, snort::Packet*, snort::MimeSession*);

int SMTP_CopyToAltBuffer(snort::Packet*, const uint8_t*, int);
const uint8_t* SMTP_GetAltBuffer(snort::Packet*, unsigned& len);
void SMTP_ResetAltBuffer(snort::Packet*);

#endif
