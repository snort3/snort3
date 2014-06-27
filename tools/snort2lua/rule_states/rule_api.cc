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
// rule_api.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <string>
#include "rule_states/rule_api.h"
#include "util/util.h"
#include "util/converter.h"

namespace rules
{


extern const ConvertMap* content_map;
extern const ConvertMap* gid_map;
extern const ConvertMap* msg_map;
extern const ConvertMap* protected_content_map;
extern const ConvertMap* rev_map;
extern const ConvertMap* sid_map;
extern const ConvertMap* uricontent_map;

const std::vector<const ConvertMap*> rule_api =
{
    content_map,
    gid_map,
    msg_map,
    protected_content_map,
    rev_map,
    sid_map,
    uricontent_map,
};

} // namespace rules
