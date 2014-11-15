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

add_library(preprocessor_states
    pps_arpspoof.cc
    pps_bo.cc
    pps_frag3_engine.cc
    pps_frag3_global.cc
    pps_ftp_telnet.cc
    pps_ftp_telnet_protocol.cc
    pps_gtp.cc
    pps_http_inspect.cc
    pps_http_inspect_server.cc
    pps_normalizers.cc
    pps_perfmonitor.cc
    pps_rpc_decode.cc
    pps_sfportscan.cc
    pps_stream5_ip.cc
    pps_stream5_global.cc
    pps_stream5_tcp.cc
    pps_stream5_udp.cc
    preprocessor_api.h
    preprocessor_api.cc
)

target_link_libraries( preprocessor_states
    snort2lua_helpers
    conversion_data
)
