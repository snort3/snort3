//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// keywords_api.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef KEYWORD_STATES_KEYWORDS_API_H
#define KEYWORD_STATES_KEYWORDS_API_H

#include <vector>
#include <memory>
#include "conversion_defines.h"

namespace keywords
{
extern const std::vector<const ConvertMap*> keywords_api;

// instantiated in kws_ruletype.cc
extern const std::vector<std::unique_ptr<const ConvertMap> > ruletype_api;
}  // namespace keywords

#endif

