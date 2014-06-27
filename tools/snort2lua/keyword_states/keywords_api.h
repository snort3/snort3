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
// keywords_api.h author Josh Rosenbaum <jorosenba@cisco.com>

#ifndef KEYWORDS_API_H
#define KEYWORDS_API_H

#include <vector>
#include <string>
#include "../conversion_state.h"

extern const std::vector<const ConvertMap*> keyword_api;

#if 0
namespace keywords
{

void add_new_rule_keyword(std::string);

}  // namespace keywords
#endif

#endif
