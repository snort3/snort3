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
// rule_content.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "rule_states/rule_api.h"
#include "utils/snort2lua_util.h"

namespace rules
{

namespace {


template<const std::string *option_name>
class Content : public ConversionState
{
public:
    Content(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Content() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace


template<const std::string *option_name>
bool Content<option_name>::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string val;
    bool retval = true;
    int pos;

    if (!(*option_name).compare("protected_content"))
        ld->make_rule_a_comment();

    val = util::get_rule_option_args(data_stream);
    retval = ld->add_rule_option(*option_name, val);
    ld->select_option(*option_name);

    pos = data_stream.tellg();
    val = util::get_rule_option_args(data_stream);
    std::istringstream subopts(val);

    while(util::get_string(subopts, keyword, ":"))
    {
        bool tmpval = true;
        val = std::string();
        std::string tmp_str;

        // get the rest of this option
        while(subopts >> tmp_str)
            val += tmp_str + " ";

        // necessary since options contain whitespace
        util::trim(keyword);
        util::trim(val);

        if (!keyword.compare("offset"))
            tmpval = ld->add_suboption("offset", val, ':');

        else if (!keyword.compare("distance"))
            tmpval = ld->add_suboption("distance", val, ':');

        else if (!keyword.compare("within"))
            tmpval = ld->add_suboption("within", val, ':');

        else if (!keyword.compare("depth"))
            tmpval = ld->add_suboption("depth", val, ':');

        else if (!keyword.compare("nocase"))
            tmpval = ld->add_suboption("nocase");

        else if (!keyword.compare("rawbytes"))
            tmpval = ld->add_rule_option_before_selected("pkt_data");

        else if (!keyword.compare("http_client_body"))
            tmpval = ld->add_rule_option_before_selected("http_client_body");

        else if (!keyword.compare("http_cookie"))
            tmpval = ld->add_rule_option_before_selected("http_cookie");

        else if (!keyword.compare("http_raw_cookie"))
            tmpval = ld->add_rule_option_before_selected("http_raw_cookie");

        else if (!keyword.compare("http_header"))
            tmpval = ld->add_rule_option_before_selected("http_header");

        else if (!keyword.compare("http_raw_header"))
            tmpval = ld->add_rule_option_before_selected("http_raw_header");

        else if (!keyword.compare("http_method"))
            tmpval = ld->add_rule_option_before_selected("http_method");

        else if (!keyword.compare("http_uri"))
            tmpval = ld->add_rule_option_before_selected("http_uri");

        else if (!keyword.compare("http_raw_uri"))
            tmpval = ld->add_rule_option_before_selected("http_raw_uri");

        else if (!keyword.compare("http_stat_code"))
            tmpval = ld->add_rule_option_before_selected("http_stat_code");

        else if (!keyword.compare("http_stat_msg"))
            tmpval = ld->add_rule_option_before_selected("http_stat_msg");

        else if (!keyword.compare("hash"))   // PROTECTED CONTENT
            tmpval = ld->add_suboption("hash", val, ':');

        else if (!keyword.compare("length"))  // PROTECTED CONTENT
            tmpval = ld->add_suboption("length", val, ':');

        else if (!keyword.compare("fast_pattern"))
        {
            if (val.empty())
                tmpval = ld->add_suboption("fast_pattern");

            else if(!val.compare("only"))
                tmpval = true;  // deprecated.  ignore.

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
                        tmpval = ld->add_suboption("fast_pattern");
                        tmpval = ld->add_suboption("fast_pattern_offset", std::to_string(offset), ':');
                        tmpval = ld->add_suboption("fast_pattern_length", std::to_string(length), ':');
                    }
                    else
                        tmpval = false;
                }
                catch(std::exception&)
                {
                    tmpval = false;
                }
            }
        }

        else
        {
            // since we don't know this next option, check for any other options
            ld->unselect_option(); // don't reference this option anymore
            data_stream.seekg(pos);
            data_stream.clear();  // Might have already hit end of stream
            return set_next_rule_state(data_stream) && retval;
        }

        if (retval)
            retval = tmpval;

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
static ConversionState* content_ctor(Converter* cv, LuaData* ld)
{
    return new Content<rule_name>(cv, ld);
}

static const std::string content = "content";
static const std::string protected_content = "protected_content";
static const std::string uricontent = "uricontent";


//  Uricontent:"foo" --> http_uti; content:"foo".
//  So, just add the 'http_uri' option first, then parse as if content
static ConversionState* uricontent_ctor(Converter* cv, LuaData* ld)
{
    ld->add_rule_option("http_uri");
    ld->add_comment_to_rule("uricontent deprecated --> 'http_uri: content:'foo'");
    return new Content<&content>(cv, ld);
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