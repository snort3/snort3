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
// kws_ruletype.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "config_states/config_api.h"
#include "keyword_states/keywords_api.h"

namespace keywords
{
const std::vector<std::unique_ptr<const ConvertMap> > ruletype_api = {};

namespace
{
enum class ParseState
{
    NAME,
    OPEN_BRACKET,
    TYPE_KEYWORD,
    TYPE_NAME,
    OUTPUT_OR_BRACKET,
    OUTPUT_ARGS
};

class RuleType : public ConversionState
{
public:
    RuleType(Converter& c) : ConversionState(c),
        state(ParseState::NAME),
        entire_line("ruletype")
    { }

    bool convert(std::istringstream& data) override;

private:
    ParseState state;
    std::string name;
    std::string type;
    std::string entire_line;
};
} // namespace

bool RuleType::convert(std::istringstream& stream)
{
    std::string val;

    if ( !entire_line.empty() )
        entire_line += "\n";

    while ( stream >> val)
    {
        entire_line += " " + val;

        switch (state)
        {
        case ParseState::NAME:
            cv.start_multiline_parsing();
            name = val;
            state = ParseState::OPEN_BRACKET;
            break;

        case ParseState::OPEN_BRACKET:
            if ( val != "{" )
            {
                std::istringstream tmp(entire_line);
                data_api.failed_conversion(tmp, val);
                return false;
            }
            state = ParseState::TYPE_KEYWORD;
            break;

        case ParseState::TYPE_KEYWORD:
            if ( val != "type" )
            {
                std::istringstream tmp(entire_line);
                data_api.failed_conversion(tmp, val);
                return false;
            }
            state = ParseState::TYPE_NAME;
            break;

        case ParseState::TYPE_NAME:
            type = val;
            state = ParseState::OUTPUT_OR_BRACKET;
            break;

        case ParseState::OUTPUT_OR_BRACKET:
            if ( val == "}" )
            {
                cv.end_multiline_parsing();

                if ( util::find_map(ruletype_api, name) != nullptr )
                {
                    std::istringstream tmp(entire_line);
                    data_api.failed_conversion(tmp, name +
                        " -- defined multiple times in configuration file");
                    return false;
                }

                const ConvertMap* map = util::find_map(keywords_api, type);

                if (map)
                {
                    // using smart pointer to guarantee new Map is deleted
                    const std::vector<std::unique_ptr<const ConvertMap> >& ruletype_map =
                        ruletype_api;
                    std::unique_ptr<ConvertMap> new_map(new ConvertMap());
                    new_map->keyword = name;
                    new_map->ctor = map->ctor;
                    const_cast<std::vector<std::unique_ptr<const ConvertMap> >&>(
                        ruletype_map).push_back(std::move(new_map));
                    return true;
                }
                else
                {
                    std::istringstream tmp(entire_line);
                    data_api.failed_conversion(tmp, "type " + type);
                    return false;
                }
            }
            else if (val == "output" )
            {
                state = ParseState::OUTPUT_ARGS;
            }
            else
            {
                std::istringstream tmp(entire_line);
                data_api.failed_conversion(tmp, "type " + type);
                return false;
            }

            break;

        case ParseState::OUTPUT_ARGS:
            // eat this argument.  Do nothing.
            break;
        }
    }

    // OUTPUT_ARGS ate up the rest of the line.
    // Now, start a new line.
    if ( state == ParseState::OUTPUT_ARGS )
        state = ParseState::OUTPUT_OR_BRACKET;

    else if ( state == ParseState::TYPE_NAME )
        return false;

    return true;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new RuleType(c); }

static const ConvertMap keyword_ruletype =
{
    "ruletype",
    ctor,
};

const ConvertMap* ruletype_map = &keyword_ruletype;
} // namepsace keywords

