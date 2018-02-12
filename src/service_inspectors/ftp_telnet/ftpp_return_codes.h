//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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
/*
 * Description:
 *
 * This file defines the return codes for the FTPTelnet functions.
 *
 * Common return codes are defined here for all functions and libraries to
 * use.  This should make function error checking easier.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 */

#ifndef FTPP_RETURN_CODES_H
#define FTPP_RETURN_CODES_H

#define FTPP_BOOL_FALSE 0
#define FTPP_SUCCESS    0

/*
 * Non-fatal errors are positive
 */
#define FTPP_BOOL_TRUE          1
#define FTPP_NONFATAL_ERR       1
#define FTPP_OUT_OF_BOUNDS      2

#define FTPP_INVALID_PROTO      3
#define FTPP_NORMALIZED         4
#define FTPP_MALFORMED_FTP_RESPONSE  5
#define FTPP_ALERTED            6
#define FTPP_NON_DIGIT          7
#define FTPP_MALFORMED_IP_PORT  8
#define FTPP_PORT_ATTACK        9

#define FTPP_INVALID_SESSION    10

#define FTPP_OR_FOUND           100
#define FTPP_OPT_END_FOUND      101
#define FTPP_CHOICE_END_FOUND   102

/*
 * Fatal errors are negative
 */
#define FTPP_FATAL_ERR         (-1)
#define FTPP_INVALID_ARG       (-2)
#define FTPP_MEM_ALLOC_FAIL    (-3)
#define FTPP_NOT_FOUND         (-4)
#define FTPP_INVALID_FILE      (-5)

#define FTPP_ALERT             (-6)

#define FTPP_INVALID_DATE      (-100)
#define FTPP_INVALID_PARAM     (-101)

#endif

