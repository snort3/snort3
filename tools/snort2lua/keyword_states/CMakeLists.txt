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


add_library( keyword_states
    kws_attribute_table.cc
    kws_config.cc
    kws_event_filter.cc
    kws_file.cc
    kws_include.cc
    kws_output.cc
    kws_paths.cc
    kws_preprocessor.cc
    kws_rule.cc
    kws_rule_state.cc
    kws_rate_filter.cc
    kws_var.cc
    kws_suppress.cc
    keywords_api.h
    keywords_api.cc
)

target_link_libraries( keyword_states
    snort2lua_helpers
    conversion_data
    output_states
    preprocessor_states
    config_states
    rule_states
)
