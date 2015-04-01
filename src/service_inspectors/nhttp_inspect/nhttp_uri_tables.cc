//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_uri_tables.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>

#include "nhttp_enum.h"
#include "nhttp_uri_norm.h"

using namespace NHttpEnums;

const CharAction UriNormalizer::uri_char[256] =
{
    CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,
    CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,
    CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,
    CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,   CHAR_INVALID,

    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_PERCENT,   CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_PATH,      CHAR_PATH,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_PATH,      CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_INVALID,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT
};

const bool UriNormalizer::good_percent[256] =
{
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false,  true, false, true,  false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false
};

