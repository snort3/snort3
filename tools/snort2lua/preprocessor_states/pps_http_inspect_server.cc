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
// pps_http_inspect_server.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"

namespace {

class HttpInspectServer : public ConversionState
{
public:
    HttpInspectServer(Converter* cv)  : ConversionState(cv) {};
    virtual ~HttpInspectServer() {};
    virtual bool convert(std::stringstream& data_stream);

private:
    static int binding_id;
};

} // namespace


#if 0

    { "profile", Parameter::PT_ENUM, profiles, "none",
      "set defaults appropriate for selected server" },

#endif

int HttpInspectServer::binding_id = 0;

bool HttpInspectServer::convert(std::stringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    if(!(data_stream >> keyword) || keyword.compare("server"))
    {
        return false;
    }

    if(!(data_stream >> keyword))
        return false;

    if(!keyword.compare("default"))
    {
        cv->open_table("http_server");
    }
    else
    {
        cv->open_table("http_server_" + std::to_string(binding_id));
        binding_id++;
        // CREATE A BINDING HERE!!
    }

    // parse the file configuration
    while(data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("extended_response_inspection"))
            tmpval = cv->add_option_to_table("extended_response_inspection", true);

        else if (!keyword.compare("allow_proxy_use"))
            tmpval = cv->add_option_to_table("allow_proxy_use", true);

        else if (!keyword.compare("inspect_gzip"))
            tmpval = cv->add_option_to_table("inspect_gzip", true);

        else if (!keyword.compare("unlimited_decompress"))
            tmpval = cv->add_option_to_table("unlimited_decompress", true);

        else if (!keyword.compare("normalize_javascript"))
            tmpval = cv->add_option_to_table("normalize_javascript", true);

        else if (!keyword.compare("enable_xff"))
            tmpval = cv->add_option_to_table("enable_xff", true);

        else if (!keyword.compare("extended_ascii_uri"))
            tmpval = cv->add_option_to_table("extended_ascii_uri", true);

        else if (!keyword.compare("non_strict"))
            tmpval = cv->add_option_to_table("non_strict", true);

        else if (!keyword.compare("inspect_uri_only"))
            tmpval = cv->add_option_to_table("inspect_uri_only", true);

        else if (!keyword.compare("tab_uri_delimiter"))
            tmpval = cv->add_option_to_table("tab_uri_delimiter", true);

        else if (!keyword.compare("normalize_headers"))
            tmpval = cv->add_option_to_table("normalize_headers", true);

        else if (!keyword.compare("normalize_utf"))
            tmpval = cv->add_option_to_table("normalize_utf", true);

        else if (!keyword.compare("log_uri"))
            tmpval = cv->add_option_to_table("log_uri", true);

        else if (!keyword.compare("normalize_cookies"))
            tmpval = cv->add_option_to_table("normalize_cookies", true);

        else if (!keyword.compare("log_hostname"))
            tmpval = cv->add_option_to_table("log_hostname", true);

        else if (!keyword.compare("no_pipeline_req"))
            tmpval = cv->add_option_to_table("no_pipeline_req", true);

        else if (!keyword.compare("ascii"))
            tmpval = parse_yn_bool_option("ascii", data_stream);

        else if (!keyword.compare("utf_8"))
            tmpval = parse_yn_bool_option("utf_8", data_stream);

        else if (!keyword.compare("u_encode"))
            tmpval = parse_yn_bool_option("u_encode", data_stream);

        else if (!keyword.compare("bare_byte"))
            tmpval = parse_yn_bool_option("bare_byte", data_stream);

        else if (!keyword.compare("iis_unicode"))
            tmpval = parse_yn_bool_option("iis_unicode", data_stream);

        else if (!keyword.compare("double_decode"))
            tmpval = parse_yn_bool_option("double_decode", data_stream);

        else if (!keyword.compare("multi_slash"))
            tmpval = parse_yn_bool_option("multi_slash", data_stream);

        else if (!keyword.compare("iis_backslash"))
            tmpval = parse_yn_bool_option("iis_backslash", data_stream);

        else if (!keyword.compare("directory"))
            tmpval = parse_yn_bool_option("directory", data_stream);

        else if (!keyword.compare("apache_whitespace"))
            tmpval = parse_yn_bool_option("apache_whitespace", data_stream);

        else if (!keyword.compare("iis_delimiter"))
            tmpval = parse_yn_bool_option("iis_delimiter", data_stream);

        else if (!keyword.compare("webroot"))
            tmpval = parse_yn_bool_option("webroot", data_stream);

        else if (!keyword.compare("max_javascript_whitespaces"))
            tmpval = parse_int_option("max_javascript_whitespaces", data_stream);

        else if (!keyword.compare("server_flow_depth"))
            tmpval = parse_int_option("server_flow_depth", data_stream);

        else if (!keyword.compare("client_flow_depth"))
            tmpval = parse_int_option("client_flow_depth", data_stream);

        else if (!keyword.compare("post_depth"))
            tmpval = parse_int_option("post_depth", data_stream);

        else if (!keyword.compare("chunk_length"))
            tmpval = parse_int_option("chunk_length", data_stream);

        else if (!keyword.compare("oversize_dir_length"))
            tmpval = parse_int_option("oversize_dir_length", data_stream);

        else if (!keyword.compare("max_header_length"))
            tmpval = parse_int_option("max_header_length", data_stream);

        else if (!keyword.compare("max_spaces"))
            tmpval = parse_int_option("max_spaces", data_stream);

        else if (!keyword.compare("max_headers"))
            tmpval = parse_int_option("max_headers", data_stream);

        else if (!keyword.compare("no_alerts"))
            cv->add_deprecated_comment("no_alerts");

        else if (!keyword.compare("decompress_swf"))
            tmpval = parse_bracketed_unsupported_list("decompress_swf", data_stream);

        else if (!keyword.compare("decompress_pdf"))
            tmpval = parse_bracketed_unsupported_list("decompress_pdf", data_stream);

        else if (!keyword.compare("http_methods"))
            tmpval = parse_curly_bracket_list("http_methods", data_stream);

        else if (!keyword.compare("whitespace_chars"))
            tmpval = parse_bracketed_byte_list("whitespace_chars", data_stream);

        else if (!keyword.compare("non_rfc_char"))
        {
            cv->add_diff_option_comment("non_rfc_char", "non_rfc_chars");
            parse_bracketed_byte_list("non_rfc_chars", data_stream);
        }

        else if (!keyword.compare("enable_cookie"))
        {
            tmpval = cv->add_option_to_table("enable_cookies", true);
            cv->add_diff_option_comment("enable_cookie", "enable_cookies");
        }

        else if (!keyword.compare("flow_depth"))
        {
            cv->add_diff_option_comment("flow_depth", "server_flow_depth");
            tmpval = parse_int_option("server_flow_depth", data_stream);
        }

        else if (!keyword.compare("ports"))
        {
            cv->add_diff_option_comment("ports", "bindings");
            cv->add_comment_to_table("check bindings table for port information");
            tmpval = parse_bracketed_unsupported_list("ports", data_stream);
        }

        else if (!keyword.compare("small_chunk_length"))
        {
            std::string bracket;
            int length;
            int consec_chunks;

            if(!(data_stream >> bracket) || bracket.compare("{") ||
                    !(data_stream >> length) ||
                    !(data_stream >> consec_chunks) ||
                    !(data_stream >> bracket) || bracket.compare("}"))
            {
                tmpval = false;
            }
            else
            {
                cv->open_table("small_chunk_length");
                cv->add_option_to_table("size", length);
                cv->add_option_to_table("count", consec_chunks);
                cv->close_table();
            }
        }

        else if (!keyword.compare("iis_unicode_map"))
        {
            std::string map_file;
            int code_page;

            if( (data_stream >> map_file) &&
                (data_stream >> code_page))
            {
                cv->open_table("iis_unicode_map");
                tmpval = cv->add_option_to_table("map_file", map_file);
                tmpval = cv->add_option_to_table("code_page", code_page) && tmpval;
                cv->close_table();
            }
            else
            {
                cv->add_comment_to_table("snort.conf missing argument for "
                    "iis_unicode_map <filename> <codemap>");
                tmpval = false;
            }
        }

        else if (!keyword.compare("profile"))
        {
            if (data_stream >> keyword)
            {
                tmpval = cv->add_option_to_table("profile", keyword);
            }
            else
            {
                cv->add_comment_to_table("Unable to convert keyword 'profile'");
                tmpval = false;
            }
        }

        else
          tmpval = false;

        retval = retval && tmpval;
    }

    return retval;
}

#if 0
// check in confg


#* decompress_swf { deflate lzma } *
#* decompress_pdf { deflate } *

#endif

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv)
{
    return new HttpInspectServer(cv);
}

static const ConvertMap preprocessor_httpinsepct_server = 
{
    "http_inspect_server",
    ctor,
};

const ConvertMap* httpinspect_server_map = &preprocessor_httpinsepct_server;

