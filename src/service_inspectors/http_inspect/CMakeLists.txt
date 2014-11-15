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
    http_inspect.cc
    hi_main.cc
    hi_main.h
    hi_ad.cc 
    hi_ad.h
    hi_client.cc 
    hi_client.h
    hi_client_norm.cc 
    hi_client_norm.h
    hi_client_stateful.h
    hi_cmd_lookup.cc 
    hi_cmd_lookup.h
    hi_include.h
    hi_mi.cc 
    hi_mi.h
    hi_norm.cc 
    hi_norm.h
    hi_paf.cc 
    hi_paf.h
    hi_events.cc
    hi_events.h
    hi_module.cc
    hi_module.h
    hi_reqmethod_check.h
    hi_return_codes.h
    hi_server.cc 
    hi_server.h
    hi_server_norm.cc 
    hi_server_norm.h
    hi_si.cc hi_si.h
    hi_stateful_inspect.h
    hi_ui_config.cc 
    hi_ui_config.h
    hi_ui_iis_unicode_map.cc 
    hi_ui_iis_unicode_map.h
    hi_util.h
    hi_util_hbm.cc 
    hi_util_hbm.h
    hi_util_kmap.cc 
    hi_util_kmap.h
    hi_util_xmalloc.cc 
    hi_util_xmalloc.h
)

# Can'be be dynamic yet
#if (STATIC_INSPECTORS)
    add_library(http_inspect STATIC ${FILE_LIST})

#else (STATIC_INSPECTORS)
#    add_shared_library(http_inspect inspectors ${FILE_LIST})

#endif (STATIC_INSPECTORS)
