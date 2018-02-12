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
// rule_content.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <string>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
template<const std::string* option_name>
class Content : public ConversionState
{
public:
    Content(Converter& c, bool val) : ConversionState(c), sticky_buffer_set(val) { }
    bool convert(std::istringstream& data) override;

private:
    bool sticky_buffer_set;
    bool parse_options(std::istringstream&, const std::string&, std::string);
    void add_sticky_buffer(std::istringstream&, const std::string& buffer);
    bool extract_payload(std::istringstream& data_stream,
        std::string& option);
};
} // namespace

template<const std::string* option_name>
void Content<option_name>::add_sticky_buffer(std::istringstream& data_stream, const std::string& buffer)
{
    if (sticky_buffer_set)
    {
        rule_api.bad_rule(data_stream, "< " + buffer + "> is the second sticky "
            "buffers set for this 'content' keyword!!");
    }

    rule_api.set_curr_options_buffer(buffer);
    sticky_buffer_set = true;
}

template<const std::string* option_name>
bool Content<option_name>::parse_options(
    std::istringstream& data_stream,
    const std::string& keyword,
    std::string val)
{
    if (keyword == "offset")
        rule_api.add_suboption("offset", val);

    else if (keyword == "distance")
        rule_api.add_suboption("distance", val);

    else if (keyword == "within")
        rule_api.add_suboption("within", val);

    else if (keyword == "depth")
        rule_api.add_suboption("depth", val);

    else if (keyword == "nocase")
        rule_api.add_suboption("nocase");

    else if (keyword == "hash")   // PROTECTED CONTENT
        rule_api.add_suboption("hash", val);

    else if (keyword == "length")  // PROTECTED CONTENT
        rule_api.add_suboption("length", val);

    else if (keyword == "rawbytes")
        add_sticky_buffer(data_stream, "pkt_data");

    else if (keyword == "http_client_body")
        add_sticky_buffer(data_stream, "http_client_body");

    else if (keyword == "http_cookie")
        add_sticky_buffer(data_stream, "http_cookie");

    else if (keyword == "http_raw_cookie")
        add_sticky_buffer(data_stream, "http_raw_cookie");

    else if (keyword == "http_header")
        add_sticky_buffer(data_stream, "http_header");

    else if (keyword == "http_raw_header")
        add_sticky_buffer(data_stream, "http_raw_header");

    else if (keyword == "http_method")
        add_sticky_buffer(data_stream, "http_method");

    else if (keyword == "http_uri")
        add_sticky_buffer(data_stream, "http_uri");

    else if (keyword == "http_raw_uri")
        add_sticky_buffer(data_stream, "http_raw_uri");

    else if (keyword == "http_stat_code")
        add_sticky_buffer(data_stream, "http_stat_code");

    else if (keyword == "http_stat_msg")
        add_sticky_buffer(data_stream, "http_stat_msg");

    else if (keyword == "fast_pattern")
    {
        if (val.empty())
        {
            rule_api.add_suboption("fast_pattern");
        }
        else if (val == "only")
        {
            static bool not_printed = true;
            if ( not_printed )
            {
                rule_api.add_comment("fast_pattern's 'only' option has been deleted");
                not_printed = false;
            }
            rule_api.add_suboption("fast_pattern");

            // FIXIT-L ideally we'd prevent doubling up nocase but in practice Talos
            // doesn't use nocase with fast_pattern:only because it is implied and
            // Snort 3 will accept contents with multiple nocase.
            rule_api.add_suboption("nocase");
        }
        else
        {
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
                    rule_api.bad_rule(data_stream, "content: wxyz: fast_pattern " + val + "," +
                        "<missing!>");
            }
            catch (std::exception&)
            {
                rule_api.bad_rule(data_stream, "content: wxyz: fast_pattern <int>,<int>");
            }
        }
    }
    else
        return false;

    return true;
}

template<const std::string* option_name>
bool Content<option_name>::extract_payload(std::istringstream& stream,
    std::string& option)
{
    if ( !stream.good() )
        return false;

    std::getline(stream, option, ',');
    if (option.empty())
        return false;

    const std::size_t quote = option.find('"');
    if ( (quote != std::string::npos) && (quote == option.rfind('"')) )
    {
        std::string tmp;
        std::getline(stream, tmp, '"');
        option += "," + tmp + "\"";
        std::getline(stream, tmp, ',');
        option += tmp;
    }

    util::trim(option);
    return true;
}

template<const std::string* option_name>
bool Content<option_name>::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string val;
    std::streamoff pos;

    if ((*option_name) == "protected_content")
        rule_api.bad_rule(data_stream, "protected_content is currently unsupported");

    std::string arg = util::get_rule_option_args(data_stream);
    std::istringstream arg_stream(arg);

    if (!extract_payload(arg_stream, val) )
    {
        rule_api.bad_rule(data_stream, "content: <missing_argument>");
        return set_next_rule_state(data_stream);
    }

    rule_api.add_option(*option_name, val);

    // This first loop parses all of the options between the
    // content keyword and the first semicolon.
    while ( extract_payload(arg_stream, keyword) )
    {
        std::istringstream opts(keyword);
        val = "";

        opts >> keyword;  // guaranteed to work since get_string is true
        std::getline(opts, val);

        util::trim(keyword);
        util::trim(val);

        if (!parse_options(data_stream, keyword, val))
            rule_api.bad_rule(data_stream, "content: " + keyword + " " + val);
    }

    pos = data_stream.tellg();
    val = util::get_rule_option_args(data_stream);
    std::istringstream subopts(val);

    // This loop parses all of the content keyword modifiers after
    // the initial semicolon.  This loop must be performed here
    // because any buffer modifiers (http_uri, http_cookie, etc_
    // must be added to the rule before the above content keyword.
    // Once we leave this method, we will have no memory of
    // 'this' current keyword.
    while (util::get_string(subopts, keyword, ":"))
    {
        val = std::string();
        std::getline(subopts, val);

        // necessary since options contain whitespace
        util::trim(keyword);
        util::trim(val);

        if (!parse_options(data_stream, keyword, val))
        {
            if (!sticky_buffer_set)
                add_sticky_buffer(data_stream, "pkt_data");

            // since this option is not an content modifier,
            // lets continue parsing the rest of the rule.
            data_stream.clear();
            data_stream.seekg(pos);
            return set_next_rule_state(data_stream);
        }

        // lets get the next keyword
        pos = data_stream.tellg();
        val = util::get_rule_option_args(data_stream);
        subopts.clear();
        subopts.str(val);
    }

    if (!sticky_buffer_set)
        add_sticky_buffer(data_stream, "pkt_data");

    // can only get here if we finish parsing this rule
    return true;
}

/**************************
 *******  A P I ***********
 **************************/

template<const std::string* rule_name>
static ConversionState* content_ctor(Converter& c)
{
    return new Content<rule_name>(c, false);
}

static const std::string content = "content";
static const std::string protected_content = "protected_content";
static const std::string uricontent = "uricontent";

//  Uricontent:"foo" --> http_uti; content:"foo".
//  So, just add the 'http_uri' option first, then parse as if content
static ConversionState* uricontent_ctor(Converter& c)
{
    c.get_rule_api().add_comment("uricontent deprecated --> 'http_uri: content:'foo'");
    c.get_rule_api().set_curr_options_buffer("http_uri", true);
    return new Content<& content>(c, true);
}

static const ConvertMap rule_content_api =
{
    content,
    content_ctor<& content>,
};

static const ConvertMap rule_protected_content_api =
{
    protected_content,
    content_ctor<& protected_content>,
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

