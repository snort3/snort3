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


if( BUILD_PROCPIDSTATS )
    set (PROCPIDSTATS_SOURCE
        sfprocpidstats.cc 
        sfprocpidstats.h
    )

endif(BUILD_PROCPIDSTATS)


add_library ( perf_monitor STATIC
    perf_monitor.cc
    perf_module.cc
    perf_module.h
    perf_base.cc
    perf_base.h
    perf_event.cc
    perf_event.h
    perf_flow.cc
    perf_flow.h
    perf.cc
    perf.h
    ${PROCPIDSTATS_SOURCE}
)
