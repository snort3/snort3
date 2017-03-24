//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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
// pps_smtp.cc author Bhagya Bantwal <bbantwal@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class Smtp : public ConversionState
{
public:
    Smtp(Converter& c) : ConversionState(c) { }
    virtual ~Smtp() { }
    virtual bool convert(std::istringstream& data_stream);

private:
    struct Command
    {
        std::string name;
        std::string format;
        int length;

        Command() : name(std::string()),
            format(std::string()),
            length(command_default_len) { }
    };

    static const int command_default_len = -1;
    std::vector<Command> commands;

    bool parse_alt_max_cmd(std::istringstream& data_stream);
    std::vector<Command>::iterator get_command(std::string cmd_name,
        std::vector<Smtp::Command>::iterator it);
};
} // namespace

std::vector<Smtp::Command>::iterator Smtp::get_command(
    std::string cmd_name,
    std::vector<Smtp::Command>::iterator it)
{
    for (; it != commands.end(); ++it)
        if (!cmd_name.compare((*it).name))
            return it;

    return commands.end();
}

bool Smtp::parse_alt_max_cmd(std::istringstream& stream)
{
    int len;
    std::string elem;
    std::string format = std::string();

    if (!(stream >> len))
        return false;

    if (!(stream >> elem) || (elem.compare("{")))
        return false;

    while (stream >> elem && elem.compare("}"))
    {

        auto it = get_command(elem, commands.begin());
        if (it == commands.end())
        {
            Command c;
            c.name = std::string(elem);
            c.length = len;
            commands.push_back(c);
        }
        else
        {
            // change the length for every command
            do
            {
                if ((*it).length < len)
                    (*it).length = len;

                it = get_command(elem, ++it);
            }
            while (it != commands.end());
        }
    }

    if (!elem.compare("}"))
        return true;
    return false;
}

bool Smtp::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    Binder bind(table_api);

    bind.set_when_proto("tcp");
    bind.set_use_type("smtp");

    table_api.open_table("smtp");

    // parse the file configuration
    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("disabled"))
        {
            table_api.add_deleted_comment("disabled");
        }
        else if (!keyword.compare("inspection_type"))
        {
            table_api.add_deleted_comment("inspection_type");
            data_stream >> keyword;
        }
        else if (!keyword.compare("enable_mime_decoding"))
        {
            table_api.add_deleted_comment("enable_mime_decoding");
        }
        else if (!keyword.compare("max_mime_depth"))
        {
            table_api.add_deleted_comment("max_mime_depth");
            data_stream >> keyword;
        }
        else if (!keyword.compare("no_alerts"))
        {
            table_api.add_deleted_comment("no_alerts");
        }
        else if (!keyword.compare("print_cmds"))
        {
            table_api.add_deleted_comment("print_cmds");
        }
        else if (!keyword.compare("alert_unknown_cmds"))
        {
            table_api.add_deleted_comment("alert_unknown_cmds");
        }
        else if (!keyword.compare("memcap"))
        {
            table_api.add_deleted_comment("memcap");
            data_stream >> keyword;
        }
        else if (!keyword.compare("max_mime_mem"))
        {
            table_api.add_deleted_comment("max_mime_mem");
            data_stream >> keyword;
        }
        else if (!keyword.compare("b64_decode_depth"))
        {
            tmpval = parse_int_option("b64_decode_depth", data_stream, false);
        }
        else if (!keyword.compare("qp_decode_depth"))
        {
            tmpval = parse_int_option("qp_decode_depth", data_stream, false);
        }
        else if (!keyword.compare("bitenc_decode_depth"))
        {
            tmpval = parse_int_option("bitenc_decode_depth", data_stream, false);
        }
        else if (!keyword.compare("uu_decode_depth"))
        {
            tmpval = parse_int_option("uu_decode_depth", data_stream, false);
        }
        else if (!keyword.compare("alt_max_command_line_len"))
        {
            tmpval = parse_alt_max_cmd(data_stream);
        }
        else if (!keyword.compare("ignore_data"))
        {
            tmpval = table_api.add_option("ignore_data", true);
        }
        else if (!keyword.compare("ignore_tls_data"))
        {
            tmpval = table_api.add_option("ignore_tls_data", true);
        }
        else if (!keyword.compare("log_filename"))
        {
            tmpval = table_api.add_option("log_filename", true);
        }
        else if (!keyword.compare("log_mailfrom"))
        {
            tmpval = table_api.add_option("log_mailfrom", true);
        }
        else if (!keyword.compare("log_rcptto"))
        {
            tmpval = table_api.add_option("log_rcptto", true);
        }
        else if (!keyword.compare("log_email_hdrs"))
        {
            tmpval = table_api.add_option("log_email_hdrs", true);
        }
        else if (!keyword.compare("email_hdrs_log_depth"))
        {
            tmpval = parse_int_option("email_hdrs_log_depth", data_stream, false);
        }
        else if (!keyword.compare("max_auth_command_line_len"))
        {
            tmpval = parse_int_option("max_auth_command_line_len", data_stream, false);
        }
        else if (!keyword.compare("max_command_line_len"))
        {
            tmpval = parse_int_option("max_command_line_len", data_stream, false);
        }
        else if (!keyword.compare("max_header_line_len"))
        {
            tmpval = parse_int_option("max_header_line_len", data_stream, false);
        }
        else if (!keyword.compare("max_response_line_len"))
        {
            tmpval = parse_int_option("max_response_line_len", data_stream, false);
        }
        else if (!keyword.compare("normalize"))
        {
            std::string norm_type;

            if (!(data_stream >> norm_type))
                data_api.failed_conversion(data_stream,  "smtp: normalize <missing_arg>");

            else if (!norm_type.compare("none"))
                table_api.add_option("normalize", "none");
            else if (!norm_type.compare("all"))
                table_api.add_option("normalize", "all");
            else if (!norm_type.compare("cmds"))
                table_api.add_option("normalize", "cmds");
            else
            {
                data_api.failed_conversion(data_stream, "smtp: normalize " + norm_type);
            }
        }
        else if (!keyword.compare("xlink2state"))
        {
            if ((data_stream >> keyword) && !keyword.compare("{"))
            {
                std::string state_type;

                if (!(data_stream >> state_type))
                    data_api.failed_conversion(data_stream,  "smtp: xlink2state <missing_arg>");

                else if (!state_type.compare("disable"))
                    table_api.add_option("xlink2state", "disable");
                else if (!state_type.compare("enabled"))
                    table_api.add_option("xlink2state", "alert");
                else if (!state_type.compare("drop"))
                    table_api.add_option("xlink2state", "drop");
                else
                {
                    data_api.failed_conversion(data_stream, "smtp: xlink2state " + state_type);
                }
                if ((data_stream >> keyword) && keyword.compare("}"))
                {
                    data_api.failed_conversion(data_stream, "smtp: xlink2state " + state_type);
                }
            }
            else
            {
                data_api.failed_conversion(data_stream, "smtp: xlink2state " + keyword);
            }
        }
        else if (!keyword.compare("auth_cmds"))
        {
            tmpval = parse_curly_bracket_list("auth_cmds", data_stream);
        }
        else if (!keyword.compare("binary_data_cmds"))
        {
            tmpval = parse_curly_bracket_list("binary_data_cmds", data_stream);
        }
        else if (!keyword.compare("data_cmds"))
        {
            tmpval = parse_curly_bracket_list("data_cmds", data_stream);
        }
        else if (!keyword.compare("normalize_cmds"))
        {
            tmpval = parse_curly_bracket_list("normalize_cmds", data_stream);
        }
        else if (!keyword.compare("invalid_cmds"))
        {
            tmpval = parse_curly_bracket_list("invalid_cmds", data_stream);
        }
        else if (!keyword.compare("valid_cmds"))
        {
            tmpval = parse_curly_bracket_list("valid_cmds", data_stream);
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

    if (!commands.empty())
    {
        table_api.open_table("alt_max_command_line_len");

        for (auto c : commands)
        {
            table_api.open_table();
            bool tmpval1 = table_api.add_option("command", c.name);
            bool tmpval2 = true;

            if (c.length != command_default_len)
                tmpval2 = table_api.add_option("length", c.length);

            table_api.close_table();

            if (!tmpval1 || !tmpval2 )
                retval = false;
        }

        table_api.close_table();
    }

    if (!ports_set)
        bind.add_when_port("25");
    bind.add_when_port("465");
    bind.add_when_port("587");
    bind.add_when_port("691");

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Smtp(c);
}

static const ConvertMap preprocessor_smtp =
{
    "smtp",
    ctor,
};

const ConvertMap* smtp_map = &preprocessor_smtp;
}

