//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
// http_common.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_COMMON_H
#define HTTP_COMMON_H

#include <cstdint>

namespace HttpCommon
{
// Field status codes for when no valid value is present in length or integer value. Positive
// values are actual length or field value.
enum StatusCode { STAT_NO_SOURCE=-16, STAT_NOT_CONFIGURED=-15, STAT_NOT_COMPUTE=-14,
    STAT_PROBLEMATIC=-12, STAT_NOT_PRESENT=-11, STAT_EMPTY_STRING=0, STAT_OTHER=1 };

// Message originator--client or server
enum SourceId { SRC__NOT_COMPUTE=-14, SRC_CLIENT=0, SRC_SERVER=1 };

} // end namespace HttpCommon

#endif

