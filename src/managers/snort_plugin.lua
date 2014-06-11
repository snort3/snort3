---------------------------------------------------------------------------
-- Copyright (C) 2014-2014 Sourcefire, Inc.
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License Version 2 as
-- published by the Free Software Foundation.  You may not use, modify or
-- distribute this program under any other version of the GNU General
-- Public License.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
---------------------------------------------------------------------------

ffi = require("ffi")

ffi.cdef[[
enum BufferType {
    BT_PAYLOAD,
    BT_HTTP_URI,
    BT_HTTP_HEADER,
    BT_HTTP_CLIENT_BODY,
    BT_HTTP_METHOD,
    BT_HTTP_COOKIE,
    BT_HTTP_STAT_CODE,
    BT_HTTP_STAT_MSG,
    BT_HTTP_RAW_URI,
    BT_HTTP_RAW_HEADER,
    BT_HTTP_RAW_COOKIE
};
struct Buffer {
    enum BufferType type;
    const uint8_t* data;
    uint32_t len;
};
const struct Buffer* get_buffer(enum BufferType);
]]

function get_buffer_type(type)
    if ( type ) then
        type = type:lower()
    end
    if ( type == nil or type == 'payload' ) then
        return ffi.C.BT_PAYLOAD
    end
    if ( type == 'http_uri' ) then
        return ffi.C.BT_HTTP_URI
    end
    if ( type == 'http_header' ) then
        return ffi.C.BT_HTTP_HEADER
    end
    if ( type == 'http_client_body' ) then
        return ffi.C.BT_HTTP_CLIENT_BODY
    end
    if ( type == 'http_method' ) then
        return ffi.C.BT_HTTP_METHOD
    end
    if ( type == 'http_cookie' ) then
        return ffi.C.BT_HTTP_COOKIE
    end
    if ( type == 'http_stat_code' ) then
        return ffi.C.BT_HTTP_STAT_CODE
    end
    if ( type == 'http_stat_msg' ) then
        return ffi.C.BT_HTTP_STAT_MSG
    end
    if ( type == 'http_raw_uri' ) then
        return ffi.C.BT_HTTP_RAW_URI
    end
    if ( type == 'http_raw_header' ) then
        return ffi.C.BT_HTTP_RAW_HEADER
    end
    if ( type == 'http_raw_cookie' ) then
        return ffi.C.BT_HTTP_RAW_COOKIE
    end
    return -1
end

