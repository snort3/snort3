//---------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
//---------------------------------------------------------------------------
// http_field_buffer.h author Cisco

#ifndef HTTP_FIELD_BUFFER_H
#define HTTP_FIELD_BUFFER_H

#include "http_buffer_info.h"
#include "http_cache_data.h"
#include "http_field.h"

class HttpMsgSection;

const Field& get_http_tmp_buffer(HttpCacheData& cache, const HttpBufferInfo& buf, HttpMsgSection* section);

class HttpTmpFieldBuffer
{
public:
    static const Field& get_buffer_data(unsigned int type);
};

#endif
