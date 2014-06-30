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
// keywords_api.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "keyword_states/keywords_api.h"


namespace keywords
{

extern const ConvertMap *portvar_map;
extern const ConvertMap *ipvar_map;
extern const ConvertMap *var_map;
extern const ConvertMap *output_map;
extern const ConvertMap *config_map;
extern const ConvertMap *preprocessor_map;
extern const ConvertMap *include_map;
extern const ConvertMap *supress_map;
extern const ConvertMap* alert_map;
extern const ConvertMap* log_map;
extern const ConvertMap* pass_map;
extern const ConvertMap* drop_map;
extern const ConvertMap* reject_map;
extern const ConvertMap* sdrop_map;
extern const ConvertMap* activate_map;
extern const ConvertMap* dynamic_map;


const std::vector<const ConvertMap*> keywords_api =
{
    portvar_map,
    ipvar_map,
    var_map,
    output_map,
    config_map,
    preprocessor_map,
    include_map,
    supress_map,
    alert_map,
    log_map,
    pass_map,
    drop_map,
    reject_map,
    sdrop_map,
    activate_map,
    dynamic_map,
};


} // namespace keywords

