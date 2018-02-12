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

// sip_utils.h author Hui Cao <huica@cisco.com>

#ifndef SIP_UTILS_H
#define SIP_UTILS_H

// Utility functions for SIP inspector

#include "sip_config.h"

int SIP_TrimSP(const char*, const char*, const char**, const char**);
SIPMethodNode* SIP_FindMethod(SIPMethodlist, const char* method, unsigned int);
uint32_t strToHash(const char*, int);

#endif

