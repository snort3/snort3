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
// config_classification.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class Classification : public ConversionState
{
public:
    Classification(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Classification::convert(std::istringstream& data_stream)
{
    std::string keyword;
    int priority;

    table_api.open_table("classifications");
    table_api.open_table();
    std::getline(data_stream, keyword, ',');

    if (data_stream.bad())
        return false;

    util::trim(keyword);
    table_api.add_option("name", keyword);
    keyword.clear();
    std::getline(data_stream, keyword, ',');

    if (data_stream.bad())
        return false;

    util::trim(keyword);
    table_api.add_option("text", keyword);

    if (!(data_stream >> priority))
        return false;

    table_api.add_option("priority", priority);
    return true;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Classification(c);
}

static const ConvertMap classification_api =
{
    "classification",
    ctor,
};

const ConvertMap* classification_map = &classification_api;
} // namespace config

