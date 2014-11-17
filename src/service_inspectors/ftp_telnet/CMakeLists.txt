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
    ft_main.cc
    ft_main.h
    ftp.cc
    ftp_data.cc
    ftp_data.h
    ftp_bounce_lookup.cc
    ftp_bounce_lookup.h
    ftp_client.h
    ftp_cmd_lookup.cc
    ftp_cmd_lookup.h
    ftp_module.cc
    ftp_module.h
    ftp_parse.cc
    ftp_parse.h
    ftp_print.cc
    ftp_print.h
    ftp_server.h
    ftp_splitter.h
    ftp_splitter.cc
    ftpp_include.h
    ftpp_return_codes.h
    ftpp_si.cc
    ftpp_si.h
    ftpp_ui_config.cc
    ftpp_ui_config.h
    ftpp_util_kmap.h
    hi_util_kmap.cc
    hi_util_kmap.h
    hi_util_xmalloc.cc
    hi_util_xmalloc.h
    pp_ftp.cc
    pp_ftp.h
    pp_telnet.cc
    pp_telnet.h
    telnet.cc
    telnet.h
    telnet_module.cc
    telnet_module.h
)

if (STATIC_INSPECTORS)
    add_library(ftp_telnet STATIC ${FILE_LIST})
    target_link_libraries(ftp_telnet utils)

else (STATIC_INSPECTORS)
   add_shared_library(ftp_telnet inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

