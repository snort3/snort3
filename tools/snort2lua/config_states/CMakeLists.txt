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


add_library( config_states
    config_alertfile.cc
    config_binding.cc
    config_checksums.cc
    config_classification.cc
    config_decode_esp.cc
    config_default_rule_state.cc
    config_deleted.cc
    config_detection.cc
    config_event_trace.cc
    config_file.cc
    config_event_queue.cc
    config_ignore_ports.cc
    config_ipv6_frag.cc
    config_memcaps.cc
    config_mpls_payload_type.cc
    config_policy_id.cc
    config_no_option.cc
    config_one_int_option.cc
    config_one_string_option.cc
    config_order.cc
    config_paf_max.cc
    config_ppm.cc
    config_profile.cc
    config_reference.cc
    config_response.cc
    config_tunnel_verdicts.cc
    config_api.h
    config_api.cc
)

target_link_libraries( config_states
    snort2lua_helpers
    conversion_data
)
