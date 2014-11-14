## Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License Version 2 as
## published by the Free Software Foundation.  You may not use, modify or
## distribute this program under any other version of the GNU General
## Public License.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

add_library( rule_states
    rule_base64_decode.cc
    rule_content.cc
    rule_file_data.cc
    rule_http_encode.cc
    rule_isdataat.cc
    rule_metadata.cc
    rule_pcre.cc
    rule_react.cc
    rule_resp.cc
    rule_stream_reassemble.cc
    rule_tag.cc
    rule_threshold.cc
    rule_unchanged.cc
    rule_urilen.cc
    rule_api.cc
    rule_api.h
)

target_link_libraries( rule_states
    snort2lua_helpers
    conversion_data
)
