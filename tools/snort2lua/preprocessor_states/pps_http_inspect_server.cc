//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// pps_http_inspect_server.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class HttpInspectServer : public ConversionState
{
public:
    HttpInspectServer(Converter& c) : ConversionState(c) { }
    virtual ~HttpInspectServer() { }
    virtual bool convert(std::istringstream& data_stream);

private:
    static int binding_id;
};
} // namespace

#if 0

{ "profile", Parameter::PT_ENUM, profiles, "none",
  "set defaults appropriate for selected server" },

#endif

int HttpInspectServer::binding_id = 0;

bool HttpInspectServer::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    Binder bind(table_api);

    bind.set_when_proto("tcp");
    bind.set_use_type("http_inspect");

    if (!(data_stream >> keyword) || keyword.compare("server"))
    {
        return false;
    }

    if (!(data_stream >> keyword))
        return false;

    if (!keyword.compare("default"))
    {
        table_api.open_table("http_inspect");
        table_api.add_diff_option_comment("http_inspect_server", "http_inspect");
    }
    else
    {
        std::string table_name = "http_inspect_" + std::to_string(binding_id);
        bind.set_use_name(table_name);
        table_api.open_table(table_name);
        binding_id++;

        if (!keyword.compare("{"))
        {
            std::string tmp;

            while (data_stream >> tmp && tmp.compare("}"))
                bind.add_when_net(tmp);

            if (!data_stream.good())
                return false;
        }
        else
        {
            bind.add_when_net(keyword);
        }
    }

    // parse the file configuration
    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("extended_response_inspection"))
            tmpval = table_api.add_option("extended_response_inspection", true);

        else if (!keyword.compare("allow_proxy_use"))
            tmpval = table_api.add_option("allow_proxy_use", true);

        else if (!keyword.compare("inspect_gzip"))
            tmpval = table_api.add_option("inspect_gzip", true);

        else if (!keyword.compare("unlimited_decompress"))
            tmpval = table_api.add_option("unlimited_decompress", true);

        else if (!keyword.compare("normalize_javascript"))
        {
            table_api.add_diff_option_comment("normalize_javascript",
                "profile.normalize_javascript");
            table_api.open_table("profile");
            table_api.append_option("normalize_javascript", true);
            table_api.close_table();
        }
        else if (!keyword.compare("enable_xff"))
            tmpval = table_api.add_option("enable_xff", true);

        else if (!keyword.compare("extended_ascii_uri"))
            tmpval = table_api.add_option("extended_ascii_uri", true);

        else if (!keyword.compare("non_strict"))
        {
            table_api.add_diff_option_comment("non_strict", "profile.non_strict");
            table_api.open_table("profile");
            table_api.append_option("non_strict", true);
            table_api.close_table();
        }
        else if (!keyword.compare("inspect_uri_only"))
            tmpval = table_api.add_option("inspect_uri_only", true);

        else if (!keyword.compare("tab_uri_delimiter"))
            tmpval = table_api.add_option("tab_uri_delimiter", true);

        else if (!keyword.compare("normalize_headers"))
            tmpval = table_api.add_option("normalize_headers", true);

        else if (!keyword.compare("normalize_utf"))
        {
            table_api.add_diff_option_comment("normalize_utf", "profile.normalize_utf");
            table_api.open_table("profile");
            table_api.append_option("normalize_utf", true);
            table_api.close_table();
        }
        else if (!keyword.compare("log_uri"))
            tmpval = table_api.add_option("log_uri", true);

        else if (!keyword.compare("normalize_cookies"))
            tmpval = table_api.add_option("normalize_cookies", true);

        else if (!keyword.compare("log_hostname"))
            tmpval = table_api.add_option("log_hostname", true);

        else if (!keyword.compare("no_pipeline_req"))
            tmpval = table_api.add_option("no_pipeline_req", true);

        else if (!keyword.compare("ascii"))
        {
            table_api.add_diff_option_comment("ascii", "profile.ascii");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("ascii", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("utf_8"))
        {
            table_api.add_diff_option_comment("utf_8", "profile.utf_8");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("utf_8", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("u_encode"))
        {
            table_api.add_diff_option_comment("u_encode", "profile.u_encode");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("u_encode", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("bare_byte"))
        {
            table_api.add_diff_option_comment("bare_byte", "profile.bare_byte");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("bare_byte", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("iis_unicode"))
        {
            table_api.add_diff_option_comment("iis_unicode", "profile.iis_unicode");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("iis_unicode", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("double_decode"))
        {
            table_api.add_diff_option_comment("double_decode", "profile.double_decode");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("double_decode", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("multi_slash"))
        {
            table_api.add_diff_option_comment("multi_slash", "profile.multi_slash");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("multi_slash", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("iis_backslash"))
        {
            table_api.add_diff_option_comment("iis_backslash", "profile.iis_backslash");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("iis_backslash", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("directory"))
        {
            table_api.add_diff_option_comment("directory", "profile.directory");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("directory", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("apache_whitespace"))
        {
            table_api.add_diff_option_comment("apache_whitespace", "profile.apache_whitespace");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("apache_whitespace", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("iis_delimiter"))
        {
            table_api.add_diff_option_comment("iis_delimiter", "profile.iis_delimiter");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("iis_delimiter", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("webroot"))
        {
            table_api.add_diff_option_comment("webroot", "profile.webroot");
            table_api.open_table("profile");
            tmpval = parse_yn_bool_option("webroot", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("max_javascript_whitespaces"))
        {
            table_api.add_diff_option_comment("max_javascript_whitespaces",
                "profile.max_javascript_whitespaces");
            table_api.open_table("profile");
            tmpval = parse_int_option("max_javascript_whitespaces", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("server_flow_depth"))
        {
            table_api.add_diff_option_comment("server_flow_depth [-1:65495]",
                "profile.server_flow_depth [-1:65535]");
            table_api.open_table("profile");
            tmpval = parse_int_option("server_flow_depth", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("client_flow_depth"))
        {
            table_api.add_diff_option_comment("client_flow_depth", "profile.client_flow_depth");
            table_api.open_table("profile");
            tmpval = parse_int_option("client_flow_depth", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("chunk_length"))
        {
            table_api.add_diff_option_comment("chunk_length", "profile.chunk_length");
            table_api.open_table("profile");
            tmpval = parse_int_option("chunk_length", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("oversize_dir_length"))
            tmpval = parse_int_option("oversize_dir_length", data_stream, false);

        else if (!keyword.compare("max_header_length"))
        {
            table_api.add_diff_option_comment("max_header_length", "profile.max_header_length");
            table_api.open_table("profile");
            tmpval = parse_int_option("max_header_length", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("max_spaces"))
        {
            table_api.add_diff_option_comment("max_spaces", "profile.max_spaces");
            table_api.open_table("profile");
            tmpval = parse_int_option("max_spaces", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("max_headers"))
        {
            table_api.add_diff_option_comment("max_headers", "profile.max_headers");
            table_api.open_table("profile");
            tmpval = parse_int_option("max_headers", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("no_alerts"))
            table_api.add_deleted_comment("no_alerts");

        else if (!keyword.compare("decompress_swf"))
            tmpval = parse_bracketed_unsupported_list("decompress_swf", data_stream);

        else if (!keyword.compare("decompress_pdf"))
            tmpval = parse_bracketed_unsupported_list("decompress_pdf", data_stream);

        else if (!keyword.compare("http_methods"))
            tmpval = parse_curly_bracket_list("http_methods", data_stream);

        else if (!keyword.compare("whitespace_chars"))
        {
            table_api.add_diff_option_comment("whitespace_chars", "profile.whitespace_chars");
            table_api.open_table("profile");
            tmpval = parse_bracketed_byte_list("whitespace_chars", data_stream);
            table_api.close_table();
        }
        else if (!keyword.compare("base36"))
            tmpval = eat_option(data_stream);

        else if (!keyword.compare("post_depth"))
        {
            table_api.add_diff_option_comment("post_depth [-1:65495]",
                "profile.post_depth [-1:65535]");
            table_api.open_table("profile");
            tmpval = parse_int_option("post_depth", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("non_rfc_char"))
        {
            table_api.add_diff_option_comment("non_rfc_char", "non_rfc_chars");
            parse_bracketed_byte_list("non_rfc_chars", data_stream);
        }
        else if (!keyword.compare("enable_cookie"))
        {
            tmpval = table_api.add_option("enable_cookies", true);
            table_api.add_diff_option_comment("enable_cookie", "enable_cookies");
        }
        else if (!keyword.compare("flow_depth"))
        {
            table_api.add_diff_option_comment("flow_depth_depth [-1:65495]",
                "profile.flow_depth [-1:65535]");
            table_api.open_table("profile");
            table_api.add_diff_option_comment("flow_depth", "server_flow_depth");
            tmpval = parse_int_option("server_flow_depth", data_stream, true);
            table_api.close_table();
        }
        else if (!keyword.compare("ports"))
        {
            std::string tmp = "";
            table_api.add_diff_option_comment("ports", "bindings");

            if ((data_stream >> keyword) && !keyword.compare("{"))
            {
                while (data_stream >> keyword && keyword.compare("}"))
                {
                    ports_set = true;
                    bind.add_when_port(keyword);
                }
            }
            else
            {
                data_api.failed_conversion(data_stream, "ports <bracketed_port_list>");
                retval = false;
            }
        }
        else if (!keyword.compare("small_chunk_length"))
        {
            std::string bracket;
            int length;
            int consec_chunks;

            if (!(data_stream >> bracket) || bracket.compare("{") ||
                !(data_stream >> length) ||
                !(data_stream >> consec_chunks) ||
                !(data_stream >> bracket) || bracket.compare("}"))
            {
                tmpval = false;
            }
            else
            {
                table_api.open_table("small_chunk_length");
                table_api.add_option("size", length);
                table_api.add_option("count", consec_chunks);
                table_api.close_table();
            }
        }
        else if (!keyword.compare("iis_unicode_map"))
        {
            std::string map_file;
            int code_page;

            table_api.open_table("profile");

            if ( (data_stream >> map_file) &&
                (data_stream >> code_page))
            {
                table_api.open_table("iis_unicode_map");
                tmpval = table_api.add_option("map_file", map_file);
                tmpval = table_api.add_option("code_page", code_page) && tmpval;
                table_api.close_table();
            }
            else
            {
                data_api.failed_conversion(data_stream, "iis_unicode_map <filename> <codemap>");
                retval = false;
            }
            table_api.close_table();
        }
        else if (!keyword.compare("profile"))
        {
            if (data_stream >> keyword)
            {
                if (!keyword.compare("all"))
                {
                    std::string profile_name = "http_profile_default";
                    tmpval = table_api.add_option("profile", "$" + profile_name);
                }
                else
                {
                    std::string profile_name = "http_profile_" + keyword;
                    tmpval = table_api.add_option("profile", "$" + profile_name);
                }
            }
            else
            {
                data_api.failed_conversion(data_stream, "profile <string>");
                retval = false;
            }
        }
        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, keyword);
            retval = false;
        }
    }

    if (!ports_set)
        bind.add_when_port("80");

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new HttpInspectServer(c);
}

static const ConvertMap preprocessor_httpinsepct_server =
{
    "http_inspect_server",
    ctor,
};

const ConvertMap* httpinspect_server_map = &preprocessor_httpinsepct_server;
}

