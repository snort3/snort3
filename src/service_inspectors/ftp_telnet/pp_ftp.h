//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
 * Header file for FTPTelnet FTP Module
 *
 * This file defines the ftp checking functions
 *
 * NOTES:
 *  - 20.09.04:  Initial Development.  SAS
 *
 * Steven A. Sturges <ssturges@sourcefire.com>
 */
#ifndef PP_FTP_H
#define PP_FTP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

//#include "protocols/packet.h"
#include "ftpp_ui_config.h"
#include "ftpp_si.h"

/* list of function prototypes for this preprocessor */
extern int check_ftp(FTP_SESSION* session, Packet* p, int iMode);

extern int initialize_ftp(FTP_SESSION* session, Packet* p, int iMode);

#endif

