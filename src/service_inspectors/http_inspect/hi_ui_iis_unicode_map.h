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
**  @author     Daniel Roelker <droelker@sourcefire.com>
*/
#ifndef HI_UI_IIS_UNICODE_MAP_H
#define HI_UI_IIS_UNICODE_MAP_H

#include "hi_include.h"
#include "hi_ui_config.h"

/*
**  This is the define for the iis_unicode_map array when there is no
**  ASCII mapping.
*/
#define HI_UI_NON_ASCII_CODEPOINT -1

int hi_ui_parse_iis_unicode_map(uint8_t** iis_unicode_map, char* filename, int iCodePage);

bool get_default_unicode_map(uint8_t*& map, int& page);

#endif

