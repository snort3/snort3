//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// sf_email_attach_decode.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef SF_EMAIL_ATTACH_DECODE_H
#define SF_EMAIL_ATTACH_DECODE_H

// Email attachment decoder

#include <stdlib.h>

#include "main/snort_types.h"

int sf_qpdecode(char* src, uint32_t slen, char* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied);

int sf_uudecode(uint8_t* src, uint32_t slen, uint8_t* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied, uint8_t* begin_found, uint8_t* end_found);

#endif

