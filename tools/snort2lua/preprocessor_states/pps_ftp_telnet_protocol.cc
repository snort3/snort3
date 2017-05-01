//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// pps_ftp_telnet_protocol.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
/****************************************
 *******  FtpServer Protocol  ***********
 ****************************************/

namespace
{
class FtpServer : public ConversionState
{
public:
    FtpServer(Converter& c) : ConversionState(c) { }
    virtual ~FtpServer() { }
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
    static int ftpsever_binding_id;
    std::vector<Command> commands;

    bool parse_alt_max_cmd(std::istringstream& data_stream);
    bool parse_cmd_validity_cmd(std::istringstream& data_stream);
    std::vector<Command>::iterator get_command(std::string cmd_name,
        std::vector<FtpServer::Command>::iterator it);
};
}  // namespace

int FtpServer::ftpsever_binding_id = 1;

std::vector<FtpServer::Command>::iterator FtpServer::get_command(
    std::string cmd_name,
    std::vector<FtpServer::Command>::iterator it)
{
    for (; it != commands.end(); ++it)
        if (!cmd_name.compare((*it).name))
            return it;

    return commands.end();
}

bool FtpServer::parse_alt_max_cmd(std::istringstream& stream)
{
    int len;
    std::string elem;
    std::string format = std::string();

    if (!(stream >> len))
        return false;

    table_api.open_table("cmd_validity");
    table_api.add_diff_option_comment("alt_max_param_len", "cmd_validity");
    table_api.close_table();

    if (!(stream >> elem) || (elem.compare("{")))
        return false;

    while (stream >> elem && elem.compare("}"))
    {
        auto it = get_command(elem, commands.begin()); // it == iterator

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

bool FtpServer::parse_cmd_validity_cmd(std::istringstream& data_stream)
{
    std::string command;
    std::string elem;

    if (!(data_stream >> command) ||
        !(data_stream >> elem) ||
        (elem.compare("<")))
        return false;

    std::string format = "<";
    while ((data_stream >> elem) && (elem.compare(">")))
        format += " " + elem;

    // last element must be a '>'
    if (elem.compare(">"))
        return false;

    format += " >";
    auto it = get_command(command, commands.begin());

    if (it == commands.end())
    {
        Command c;
        c.name = std::string(command);
        c.format = std::string(format);
        commands.push_back(c);
    }
    // command exists, but format unspecified (length likely specified)
    else if (it->format.empty())
    {
        it->format = std::string(format);
    }
    // command && format exists, but format is different. create new command
    else if (format.compare(it->format))
    {
        Command c;
        c.name = std::string(command);
        c.format = std::string(format);
        c.length = it->length;
        commands.push_back(c);
    }
    else
    {
        // the two format names and options are identical.
        // do nothing
    }

    return true;
}

bool FtpServer::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    Binder bind(table_api);
    bind.set_use_type("ftp_server");
    bind.set_when_proto("tcp");

    if (data_stream >> keyword)
    {
        if (!keyword.compare("default"))
        {
            table_api.open_table("ftp_server");
        }
        else
        {
            std::string table_name = "ftp_server_target_" + std::to_string(ftpsever_binding_id);
            bind.set_use_name(table_name);
            table_api.open_table(table_name);
            ftpsever_binding_id++;

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
    }
    else
    {
        return false;
    }

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("print_cmds"))
            tmpval = table_api.add_option("print_cmds", true);

        else if (!keyword.compare("def_max_param_len"))
            tmpval = parse_int_option("def_max_param_len", data_stream, false);

        else if (!keyword.compare("telnet_cmds"))
            tmpval = parse_yn_bool_option("telnet_cmds", data_stream, false);

        else if (!keyword.compare("ignore_telnet_erase_cmds"))
            tmpval = parse_yn_bool_option("ignore_telnet_erase_cmds", data_stream, false);

        else if (!keyword.compare("ignore_data_chan"))
            tmpval = parse_yn_bool_option("ignore_data_chan", data_stream, false);

        else if (!keyword.compare("ftp_cmds"))
            tmpval = parse_curly_bracket_list("ftp_cmds", data_stream);

        else if (!keyword.compare("chk_str_fmt"))
            tmpval = parse_curly_bracket_list("chk_str_fmt", data_stream);

        else if (!keyword.compare("alt_max_param_len"))
            tmpval = parse_alt_max_cmd(data_stream);

        else if (!keyword.compare("cmd_validity"))
            tmpval = parse_cmd_validity_cmd(data_stream);

        else if (!keyword.compare("data_chan_cmds"))
            tmpval = parse_curly_bracket_list("data_chan_cmds", data_stream);

        else if (!keyword.compare("data_rest_cmds"))
            tmpval = parse_curly_bracket_list("data_rest_cmds", data_stream);

        else if (!keyword.compare("data_xfer_cmds"))
            tmpval = parse_curly_bracket_list("data_xfer_cmds", data_stream);

        else if (!keyword.compare("file_put_cmds"))
            tmpval = parse_curly_bracket_list("file_put_cmds", data_stream);

        else if (!keyword.compare("file_get_cmds"))
            tmpval = parse_curly_bracket_list("file_get_cmds", data_stream);

        else if (!keyword.compare("data_chan"))
        {
            table_api.add_diff_option_comment("data_chan", "ignore_data_chan");
            tmpval = table_api.add_option("ignore_data_chan", true);
        }
        else if (!keyword.compare("ports"))
        {
            table_api.add_diff_option_comment("ports", "bindings");
            table_api.add_comment("check bindings table for port information");

            if ((data_stream >> keyword) && !keyword.compare("{"))
            {
                while (data_stream >> keyword && keyword.compare("}"))
                {
                    bind.add_when_port(keyword);
                    ports_set = true;
                }
            }
            else
            {
                tmpval = false;
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
        table_api.open_table("cmd_validity");

        for (auto c : commands)
        {
            table_api.open_table();
            bool tmpval1 = table_api.add_option("command", c.name);
            bool tmpval2 = true;
            bool tmpval3 = true;

            if (!c.format.empty())
            {
                std::istringstream tmp_stream (c.format);
                std::string tmp_string;

                // If there is a variable present, need to handle correctly.
                // Therefore, add as list since that already handles variables
                while (tmp_stream >> tmp_string)
                    if (!table_api.add_list("format", tmp_string))
                        tmpval2 = false;
            }

            if (c.length != command_default_len)
                tmpval3 = table_api.add_option("length", c.length);

            table_api.close_table();

            if (!tmpval1 || !tmpval2 || !tmpval3)
                retval = false;
        }

        table_api.close_table();
    }

    if (!ports_set)
        bind.add_when_port("21");

    return retval;
}

/****************************************
 *******  FtpClient Protocol  ***********
 ****************************************/

namespace
{
class FtpClient : public ConversionState
{
public:
    FtpClient(Converter& c) : ConversionState(c) { }
    virtual ~FtpClient() { }
    virtual bool convert(std::istringstream& data_stream);

private:
    static int ftpclient_binding_id;
};
} // namespace

int FtpClient::ftpclient_binding_id = 1;

bool FtpClient::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    Binder bind(table_api);
    bind.set_use_type("ftp_client");
    bind.set_when_proto("tcp");

    if (data_stream >> keyword)
    {
        if (!keyword.compare("default"))
        {
            bind.set_when_service("ftp");
            table_api.open_table("ftp_client");
        }
        else
        {
            std::string table_name = "ftp_client_target_" +
                std::to_string(ftpclient_binding_id);
            bind.set_use_name(table_name);
            table_api.open_table(table_name);
            ftpclient_binding_id++;

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
    }
    else
    {
        return false;
    }

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("telnet_cmds"))
            tmpval = parse_yn_bool_option("telnet_cmds", data_stream, false);

        else if (!keyword.compare("ignore_telnet_erase_cmds"))
            tmpval = parse_yn_bool_option("ignore_telnet_erase_cmds", data_stream, false);

        else if (!keyword.compare("max_resp_len"))
            tmpval = parse_int_option("max_resp_len", data_stream, false);

        else if (!keyword.compare("bounce"))
            tmpval = parse_yn_bool_option("bounce", data_stream, false);

        // add bounce_to as a commented list
        else if (!keyword.compare("bounce_to"))
        {
            // get rid of the "{"
            if (!(data_stream >> keyword) && keyword.compare("{"))
            {
                data_api.failed_conversion(data_stream, "bounce_to");
                retval = false;
            }
            else
            {
                table_api.open_table("bounce_to");

                while (data_stream >> keyword && keyword.compare("}"))
                {
                    std::istringstream bounce_stream(keyword);
                    std::string data;
                    bool tmpval1 = true, tmpval2 = true, tmpval3 = true;
                    table_api.open_table();

                    if (util::get_string(bounce_stream, data, ","))
                        tmpval1 = table_api.add_option("address", data);

                    if (util::get_string(bounce_stream, data, ","))
                        tmpval2 = table_api.add_option("port", std::stoi(data));

                    if (util::get_string(bounce_stream, data, ","))
                        tmpval3 = table_api.add_option("last_port", std::stoi(data));

                    // shouldn't be a fourth argument
                    if (!tmpval1 || !tmpval2 || !tmpval3 ||
                        util::get_string(bounce_stream, data, ","))
                    {
                        data_api.failed_conversion(data_stream, "bounce_to");
                        retval = false;
                    }

                    table_api.close_table(); // anonymous
                }
                table_api.close_table(); // "bounce_to"
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

    return retval;
}

/****************************************
 *********  Telnet Protocol  ************
 ****************************************/

namespace
{
class Telnet : public ConversionState
{
public:
    Telnet(Converter& c) : ConversionState(c) { }
    virtual ~Telnet() { }
    virtual bool convert(std::istringstream& data_stream);
};
} // namespace

bool Telnet::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool ports_set = false;
    bool retval = true;
    Binder bind(table_api);

    bind.set_when_proto("tcp");
    bind.set_use_type("telnet");
    table_api.open_table("telnet");

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("normalize"))
            tmpval = table_api.add_option("normalize", true);

        else if (!keyword.compare("detect_anomalies"))
            table_api.add_deleted_comment("detect_anomalies");

        else if (!keyword.compare("ayt_attack_thresh"))
        {
            int i_val;

            if (data_stream >> i_val)
                tmpval = table_api.add_option("ayt_attack_thresh", i_val);
            else
                tmpval = false;
        }
        else if (!keyword.compare("ports"))
        {
            table_api.add_diff_option_comment("ports", "bindings");
            table_api.add_comment("check bindings table for port information");

            // adding ports to the binding.
            if ((data_stream >> keyword) && !keyword.compare("{"))
            {
                while (data_stream >> keyword && keyword != "}")
                {
                    ports_set = true;
                    bind.add_when_port(keyword);
                }
            }
            else
            {
                data_api.failed_conversion(data_stream, "ports - invalid port list");
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

    // adding the default port.
    if (!ports_set)
        bind.add_when_port("23");

    return retval;
}

/****************************************
 *******  FtpTelnetProtocol  ************
 ****************************************/

namespace
{
class FtpTelnetProtocol : public ConversionState
{
public:
    FtpTelnetProtocol(Converter& c) : ConversionState(c) { }
    virtual ~FtpTelnetProtocol() { }
    virtual bool convert(std::istringstream& data_stream);
};
} // namespace

bool FtpTelnetProtocol::convert(std::istringstream& data_stream)
{
    std::string protocol;

    if (data_stream >> protocol)
    {
        if (!protocol.compare("telnet"))
        {
            cv.set_state(new Telnet(cv));
        }
        else if (!protocol.compare("ftp"))
        {
            if (data_stream >> protocol)
            {
                if (!protocol.compare("client"))
                    cv.set_state(new FtpClient(cv));

                else if (!protocol.compare("server"))
                    cv.set_state(new FtpServer(cv));

                else
                    return false;
            }
        }
        else
            return false;

        return true;
    }

    return false;
}

/*******  PUBLIC API ************/

static ConversionState* ctor(Converter& c)
{
    return new FtpTelnetProtocol(c);
}

static const ConvertMap ftptelnet_protocol_preprocessor =
{
    "ftp_telnet_protocol",
    ctor,
};

const ConvertMap* ftptelnet_protocol_map = &ftptelnet_protocol_preprocessor;
} // namespace preprocessors

