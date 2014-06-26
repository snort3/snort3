/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// config_api.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "config_states/config_api.h"


extern const ConvertMap* autogenerate_decode_rules_map;
extern const ConvertMap* flowbit_size_map;
extern const ConvertMap* checksum_map;
extern const ConvertMap* enable_gtp_map;
extern const ConvertMap* paf_max_map;
extern const ConvertMap* pcre_match_limit_map;
extern const ConvertMap* pcre_match_limit_recursion_map;


const std::vector<const ConvertMap*> config_api = 
{
    autogenerate_decode_rules_map,
    checksum_map,
    flowbit_size_map,
    enable_gtp_map,
    paf_max_map,
    pcre_match_limit_map,
    pcre_match_limit_recursion_map,
};
