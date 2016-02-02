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
**  @file       hi_return_codes.h
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file defines the return codes for the HttpInspect
**              functions.
**
**  Common return codes are defined here for all functions and libraries to
**  use.  This should make function error checking easier.
**
**  NOTES:
**
**  - 2.14.03:  Initial Development.  DJR
*/

#ifndef HI_RETURN_CODES_H
#define HI_RETURN_CODES_H

#include "hi_include.h"

#define HI_BOOL_FALSE 0
#define HI_SUCCESS    0

/*
**  Non-fatal errors are positive
*/
#define HI_BOOL_TRUE          1
#define HI_NONFATAL_ERR       1
#define HI_OUT_OF_BOUNDS      2

/*
**  Fatal errors are negative
*/
#define HI_FATAL_ERR         -1
#define HI_INVALID_ARG       -2
#define HI_MEM_ALLOC_FAIL    -3
#define HI_NOT_FOUND         -4
#define HI_INVALID_FILE      -5

#endif

