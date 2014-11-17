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


add_library (parser STATIC 
    arg_list.cc 
    arg_list.h 
    parser.cc 
    parser.h 
    parse_byte_code.cc 
    parse_byte_code.h 
    parse_conf.cc 
    parse_conf.h 
    parse_ip.cc 
    parse_ip.h 
    parse_rule.cc 
    parse_rule.h 
    parse_stream.cc 
    parse_stream.h 
    cmd_line.cc 
    cmd_line.h 
    config_file.cc 
    config_file.h 
    keywords.h 
    mstring.cc 
    mstring.h 
    vars.cc 
    vars.h
)

target_link_libraries(parser
    protocols
    time
    stream
    codecs
)
