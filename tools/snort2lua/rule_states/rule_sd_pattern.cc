//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// rule_sd_pattern.cc author Victor Roemer <viroemer@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"
#include "rule_api.h"

namespace rules
{
namespace
{
class SDPattern : public ConversionState
{
public:
    SDPattern(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
private:
    std::string convert_pattern(const std::string& pattern);
};
} // namespace

std::string SDPattern::convert_pattern(const std::string& pattern)
{
    const std::string unused_pcre_tokens("()[].+*^$|");

    std::string s3_pattern;

    for (unsigned i = 0; i < pattern.size(); ++i)
    {
        char sym = pattern[i];

        switch (sym)
        {
        case '\\':
            {
                if (i + 1 < pattern.size())
                    sym = pattern[++i];
                else
                {
                    // if backslash placed at the end of the pattern
                    // Snort2 will process it as a usual symbol
                    s3_pattern.append("\\\\");
                    break;
                }

                switch (sym)
                {
                case 'l':
                    s3_pattern.append("\\p{L}");
                    break;

                case 'L':
                    s3_pattern.append("[^\\p{L}]");
                    break;

                case 'w':
                case 'W':
                case 'd':
                case 'D':
                case '\\':
                case '{':
                case '}':
                case '?':
                    s3_pattern.push_back('\\');
                    s3_pattern.push_back(sym);
                    break;

                default:
                    // Snort2 ignores unknown escape sequences
                    break;
                }

                break;
            }

        case '{':
        case '}':
        case '?':
            s3_pattern.push_back(sym);
            break;

        default:
            if (unused_pcre_tokens.find(sym) != std::string::npos)
                s3_pattern.push_back('\\');
            s3_pattern.push_back(sym);
            break;
        }
    }

    return s3_pattern;
}

bool SDPattern::convert(std::istringstream& stream)
{
    std::string args = util::get_rule_option_args(stream);
    std::istringstream arg_stream(args);

    std::string count;

    if ( !util::get_string(arg_stream, count, ",") )
    {
        rule_api.bad_rule(stream, "sd_pattern missing threshold argument");
        return set_next_rule_state(stream);
    }

    std::string pattern = util::get_remain_data(arg_stream, false);

    if ( pattern.empty() )
    {
        rule_api.bad_rule(stream, "sd_pattern missing pattern argument");
        return set_next_rule_state(stream);
    }

    std::string s3_pattern = convert_pattern(pattern);

    rule_api.add_option("sd_pattern", "\"" + s3_pattern + "\"");
    rule_api.add_suboption("threshold", count);
    rule_api.bad_rule(stream, "sd_pattern: rules should be written with Snort3 "
        "functionality in mind");

    return set_next_rule_state(stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new SDPattern(c);
}

static const std::string sd_pattern = "sd_pattern";
static const ConvertMap sd_pattern_api =
{
    sd_pattern,
    ctor,
};

const ConvertMap* sd_pattern_map = &sd_pattern_api;
} // namespace rules

