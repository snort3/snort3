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

/**
**  @file       hi_norm.h
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      Contains function prototypes for normalization routines.
**
**  Contains stuctures and headers for normalization routines.
**
**  NOTES:
**      - Initial development.  DJR
*/
#ifndef HI_NORM_H
#define HI_NORM_H

#include <sys/types.h>

#include "hi_include.h"
#include "hi_ui_config.h"
#include "hi_si.h"

#define MAX_URI 8192

int hi_normalization(HI_SESSION* session, int iInspectMode, HttpSessionData* hsd);
int hi_norm_uri(HI_SESSION* session, u_char* uribuf,int* uribuf_size,
    const u_char* uri, int uri_size, uint16_t* encodeType);

int hi_split_header_cookie(HI_SESSION* session, u_char* header, int* i_header_len,
    u_char* cookie_header, int* i_cookie_len,
    const u_char* raw_header, int i_raw_header_len,
    COOKIE_PTR* cookie);
#endif

