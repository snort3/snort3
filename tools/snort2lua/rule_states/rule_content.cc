/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// rule_content.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "rule_states/rule_api.h"
#include "utils/s2l_util.h"

namespace rules
{

namespace {


template<const std::string *option_name>
class Content : public ConversionState
{
public:
    Content(Converter& c) : ConversionState(c) {};
    virtual ~Content() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace


template<const std::string *option_name>
bool Content<option_name>::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string val;
    std::streamoff pos;

    if (!(*option_name).compare("protected_content"))
        rule_api.bad_rule(data_stream, "protected_content is currently unsupported");

    val = util::get_rule_option_args(data_stream);
    rule_api.add_rule_option(*option_name, val);
    rule_api.select_option(*option_name);

    pos = data_stream.tellg();
    val = util::get_rule_option_args(data_stream);
    std::istringstream subopts(val);

    while(util::get_string(subopts, keyword, ":"))
    {
        val = std::string();
        std::string tmp_str;

        // get the rest of this option
        while(subopts >> tmp_str)
            val += tmp_str + " ";

        // necessary since options contain whitespace
        util::trim(keyword);
        util::trim(val);

        if (!keyword.compare("offset"))
            rule_api.add_suboption("offset", val);

        else if (!keyword.compare("distance"))
            rule_api.add_suboption("distance", val);

        else if (!keyword.compare("within"))
            rule_api.add_suboption("within", val);

        else if (!keyword.compare("depth"))
            rule_api.add_suboption("depth", val);

        else if (!keyword.compare("nocase"))
            rule_api.add_suboption("nocase");

        else if (!keyword.compare("rawbytes"))
            rule_api.add_rule_option_before_selected("pkt_data");

        else if (!keyword.compare("http_client_body"))
            rule_api.add_rule_option_before_selected("http_client_body");

        else if (!keyword.compare("http_cookie"))
            rule_api.add_rule_option_before_selected("http_cookie");

        else if (!keyword.compare("http_raw_cookie"))
            rule_api.add_rule_option_before_selected("http_raw_cookie");

        else if (!keyword.compare("http_header"))
            rule_api.add_rule_option_before_selected("http_header");

        else if (!keyword.compare("http_raw_header"))
            rule_api.add_rule_option_before_selected("http_raw_header");

        else if (!keyword.compare("http_method"))
            rule_api.add_rule_option_before_selected("http_method");

        else if (!keyword.compare("http_uri"))
            rule_api.add_rule_option_before_selected("http_uri");

        else if (!keyword.compare("http_raw_uri"))
            rule_api.add_rule_option_before_selected("http_raw_uri");

        else if (!keyword.compare("http_stat_code"))
            rule_api.add_rule_option_before_selected("http_stat_code");

        else if (!keyword.compare("http_stat_msg"))
            rule_api.add_rule_option_before_selected("http_stat_msg");

        else if (!keyword.compare("hash"))   // PROTECTED CONTENT
            rule_api.add_suboption("hash", val);

        else if (!keyword.compare("length"))  // PROTECTED CONTENT
            rule_api.add_suboption("length", val);

        else if (!keyword.compare("fast_pattern"))
        {
            if (val.empty())
                 rule_api.add_suboption("fast_pattern");

            else if(!val.compare("only"))
                rule_api.add_comment_to_rule("content's 'only' option has been deleted");

            else
            {
                // don't let the program catch for invalid syntax.
                try
                {
                    std::size_t pos;
                    int offset = std::stoi(val, &pos);
                    if (val[pos] == ',')
                    {
                        pos++;
                        int length = std::stoi(val.substr(pos, std::string::npos));
                        rule_api.add_suboption("fast_pattern");
                        rule_api.add_suboption("fast_pattern_offset", std::to_string(offset));
                        rule_api.add_suboption("fast_pattern_length", std::to_string(length));
                    }
                    else
                        rule_api.bad_rule(data_stream, "content: wxyz: fast_pattern " + val + "," + "<missing!>");
                }
                catch(std::exception&)
                {
                    rule_api.bad_rule(data_stream, "content: wxyz: fast_pattern <int>,<int>");
                }
            }
        }

        else
        {
            // since we don't know this next option, check for any other options
            rule_api.unselect_option(); // don't reference this option anymore
            data_stream.seekg(pos);
            data_stream.clear();  // Might have already hit end of stream
            return set_next_rule_state(data_stream);
        }

        // lets get the next keyword
        pos = data_stream.tellg();
        val = util::get_rule_option_args(data_stream);
        subopts.clear();
        subopts.str(val);
    };

    // can only get here if we finish parsing this rule
    return true;
}

/**************************
 *******  A P I ***********
 **************************/


template<const std::string *rule_name>
static ConversionState* content_ctor(Converter& c)
{
    return new Content<rule_name>(c);
}

static const std::string content = "content";
static const std::string protected_content = "protected_content";
static const std::string uricontent = "uricontent";


//  Uricontent:"foo" --> http_uti; content:"foo".
//  So, just add the 'http_uri' option first, then parse as if content
static ConversionState* uricontent_ctor(Converter& c)
{
    c.get_rule_api().add_rule_option("http_uri");
    c.get_rule_api().add_comment_to_rule("uricontent deprecated --> 'http_uri: content:'foo'");
    return new Content<&content>(c);
}


static const ConvertMap rule_content_api =
{
    content,
    content_ctor<&content>,
};

static const ConvertMap rule_protected_content_api =
{
    protected_content,
    content_ctor<&protected_content>,
};

static const ConvertMap rule_uricontent_api =
{
    uricontent,
    uricontent_ctor,
};


const ConvertMap* content_map = &rule_content_api;
const ConvertMap* protected_content_map = &rule_protected_content_api;
const ConvertMap* uricontent_map = &rule_uricontent_api;

} // namespace rules
