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


set (FILE_LIST
    nhttp_inspect.cc
    nhttp_inspect.h
    nhttp_msg_section.cc
    nhttp_msg_section.h
    nhttp_msg_start.cc
    nhttp_msg_start.h
    nhttp_msg_request.cc
    nhttp_msg_request.h
    nhttp_msg_status.cc
    nhttp_msg_status.h
    nhttp_msg_head_shared.cc
    nhttp_msg_head_shared.h
    nhttp_msg_header.cc
    nhttp_msg_header.h
    nhttp_msg_body.cc
    nhttp_msg_body.h
    nhttp_msg_chunk.cc
    nhttp_msg_chunk.h
    nhttp_msg_trailer.cc
    nhttp_msg_trailer.h
    nhttp_head_norm.cc
    nhttp_head_norm.h
    nhttp_uri.cc
    nhttp_uri.h
    nhttp_uri_norm.cc
    nhttp_uri_norm.h
    nhttp_normalizers.cc
    nhttp_normalizers.h
    nhttp_str_to_code.cc
    nhttp_str_to_code.h
    nhttp_api.cc nhttp_api.h
    nhttp_tables.cc
    nhttp_uri_tables.cc
    nhttp_module.cc
    nhttp_module.h
    nhttp_test_input.cc
    nhttp_test_input.h
    nhttp_flow_data.cc
    nhttp_flow_data.h
    nhttp_transaction.cc
    nhttp_transaction.h
    nhttp_scratch_pad.h
    nhttp_test_manager.cc
    nhttp_test_manager.h
    nhttp_enum.h
    nhttp_field.cc
    nhttp_field.h
    nhttp_stream_splitter.cc
    nhttp_stream_splitter.h
    nhttp_splitter.cc
    nhttp_splitter.h
)

if (STATIC_INSPECTORS)
    add_library(nhttp_inspect STATIC ${FILE_LIST})
else(STATIC_INSPECTORS)
    add_shared_library(nhttp_inspect inspectors ${FILE_LIST})
endif(STATIC_INSPECTORS)
