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
 * This file contains function definitions for bounce IP lookups.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 * Kevin Liu <kliu@sourcefire.com>
 */
#ifndef FTP_BOUNCE_LOOKUP_H
#define FTP_BOUNCE_LOOKUP_H

#include "ftpp_ui_config.h"

int ftp_bounce_lookup_init(BOUNCE_LOOKUP** BounceLookup);
int ftp_bounce_lookup_cleanup(BOUNCE_LOOKUP** BounceLookup);
int ftp_bounce_lookup_add(BOUNCE_LOOKUP* BounceLookup, const snort::SfIp* ip, FTP_BOUNCE_TO* BounceTo);

FTP_BOUNCE_TO* ftp_bounce_lookup_find(BOUNCE_LOOKUP* BounceLookup, const snort::SfIp* ip, int* iError);
// FIXIT-L orphan code until FTP client inspector acquires a show() method
// FTP_BOUNCE_TO* ftp_bounce_lookup_first(BOUNCE_LOOKUP* BounceLookup, int* iError);
// FTP_BOUNCE_TO* ftp_bounce_lookup_next(BOUNCE_LOOKUP* BounceLookup, int* iError);

#endif

