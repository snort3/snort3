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
// pps_ftp_telnet_protocol.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace preprocessors
{


/****************************************
 *******  FtpServer Protocol  ***********
 ****************************************/

namespace {

class FtpServer : public ConversionState
{
public:
    FtpServer(Converter* cv, LuaData* ld);
    virtual ~FtpServer() {};
    virtual bool convert(std::istringstream& data_stream);
private:
    struct Command
    {
        std::string name;
        std::string format;
        int length;

        inline bool operator==(Command c)
        {  return (!name.compare(c.name)); }

        Command() : name(std::string()),
                    format(std::string()),
                    length(command_default_len) {}
    };

    const static int command_default_len = -1;
    static int ftpsever_binding_id;
    std::vector<Command> commands;


    bool parse_alt_max_cmd(std::istringstream& data_stream);
    bool parse_cmd_validity_cmd(std::istringstream& data_stream);
    std::vector<Command>::iterator get_command(std::string cmd_name,
                            std::vector<FtpServer::Command>::iterator it);
};

}  // namespace

int FtpServer::ftpsever_binding_id = 1;


FtpServer::FtpServer(Converter* cv, LuaData* ld) : ConversionState(cv, ld)
{}

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

    if(!(stream >> len))
        return false;

    ld->open_table("cmd_validity");
    ld->add_diff_option_comment("alt_max_param_len", "cmd_validity");
    ld->close_table();


    if(!(stream >> elem) || (elem.compare("{")))
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
            } while (it != commands.end());
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
    while((data_stream >> elem) && (elem.compare(">")))
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

    if (data_stream >> keyword)
    {
        if(!keyword.compare("default"))
            ld->open_table("ftp_server");
        else
        {
            ld->open_table("ftp_server_target_" + std::to_string(ftpsever_binding_id));
            ftpsever_binding_id++;
            ld->add_comment_to_table("Unable to create target based ftp configuration at this time!!!");


            // TODO --   add some bindings here!!
            if (!keyword.compare("{"))
            {
                std::string list, tmp;

                while (data_stream >> tmp && tmp.compare("}"))
                    list += tmp;

                if (!data_stream.good())
                    return false;

                // this is an ip address list
            }
            else
            {
                // this is an ip address
            }
        }
    }
    else
    {
        return false;
    }

    while(data_stream >> keyword)
    {
        bool tmpval = true;


        if(!keyword.compare("print_cmds"))
            tmpval = ld->add_option_to_table("print_cmds", true);

        else if(!keyword.compare("def_max_param_len"))
            tmpval = parse_int_option("def_max_param_len", data_stream);

        else if(!keyword.compare("telnet_cmds"))
            tmpval = parse_yn_bool_option("telnet_cmds", data_stream);
        
        else if(!keyword.compare("ignore_telnet_erase_cmds"))
            tmpval = parse_yn_bool_option("ignore_telnet_erase_cmds", data_stream);

        else if(!keyword.compare("ignore_data_chan"))
            tmpval = parse_yn_bool_option("ignore_data_chan", data_stream);

        else if(!keyword.compare("ftp_cmds"))
            tmpval = parse_curly_bracket_list("ftp_cmds", data_stream);

        else if(!keyword.compare("chk_str_fmt"))
            tmpval = parse_curly_bracket_list("chk_str_fmt", data_stream);

        else if(!keyword.compare("alt_max_param_len"))
            tmpval = parse_alt_max_cmd(data_stream);

        else if(!keyword.compare("cmd_validity"))
            tmpval = parse_cmd_validity_cmd(data_stream);

        else if (!keyword.compare("data_chan_cmds"))
            tmpval = parse_curly_bracket_list("data_chan_cmds", data_stream);

        else if (!keyword.compare("data_xfer_cmds"))
            tmpval = parse_curly_bracket_list("data_xfer_cmds", data_stream);

        else if (!keyword.compare("file_put_cmds"))
            tmpval = parse_curly_bracket_list("file_put_cmds", data_stream);

        else if (!keyword.compare("file_get_cmds"))
            tmpval = parse_curly_bracket_list("file_get_cmds", data_stream);
        
        else if(!keyword.compare("data_chan"))
        {
            ld->add_diff_option_comment("data_chan", "ignore_data_chan");
            tmpval = ld->add_option_to_table("ignore_data_chan", true);
        }

        else if (!keyword.compare("ports"))
        {
            ld->add_diff_option_comment("ports", "bindings");
            ld->add_comment_to_table("check bindings table for port information");
            // add commented list for now
            std::string tmp = "";
            while (data_stream >> keyword && keyword != "}")
                tmp += " " + keyword;
            tmpval = ld->add_option_to_table("--ports", tmp + "}");
        }

        else
        {
            tmpval = false;
        }

        if (!tmpval)
            retval = false;
    }

    if (!commands.empty())
    {
        ld->open_table("cmd_validity");

        for (auto c : commands)
        {
            ld->open_table();
            bool tmpval1 = ld->add_option_to_table("command", c.name);
            bool tmpval2 = true;
            bool tmpval3 = true;

            if (!c.format.empty())
            {
                std::istringstream tmp_stream (c.format);
                std::string tmp_string;

                // If there is a variable present, need to handle correctly.
                // Therefore, add as list since that already handles variables
                while(tmp_stream >> tmp_string)
                    if (!ld->add_list_to_table("format", tmp_string))
                        tmpval2 = false;
            }

            if (c.length != command_default_len)
                tmpval3 = ld->add_option_to_table("length", c.length);

            ld->close_table();

            if (!tmpval1 || !tmpval2 || !tmpval3)
                retval = false;
        }

        ld->close_table();
    }

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
    FtpClient(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~FtpClient() {};
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

    if (data_stream >> keyword)
    {
        if(!keyword.compare("default"))
            ld->open_table("ftp_client");
        else
        {
            ld->open_table("ftp_client_target_" + std::to_string(ftpclient_binding_id));
            ftpclient_binding_id++;

            // TODO --   add some bindings here!!
            if (!keyword.compare("{"))
            {
                std::string list, tmp;

                while (data_stream >> tmp && tmp.compare("}"))
                    list += tmp;

                if (!data_stream.good())
                    return false;

                // this is an ip address list
            }
            else
            {
                // this is an ip address
            }

            ld->add_comment_to_table("Unable to create target based ftp configuration at this time!!!");
        }
    }
    else
    {
        return false;
    }

    while(data_stream >> keyword)
    {
        bool tmpval = true;


        if(!keyword.compare("telnet_cmds"))
            tmpval = parse_yn_bool_option("telnet_cmds", data_stream);

        else if(!keyword.compare("ignore_telnet_erase_cmds"))
            tmpval = parse_yn_bool_option("ignore_telnet_erase_cmds", data_stream);

        else if(!keyword.compare("max_resp_len"))
            tmpval = parse_int_option("max_resp_len", data_stream);

        else if(!keyword.compare("bounce"))
            tmpval = parse_yn_bool_option("bounce", data_stream);

        // add bounce_to as a commented list
        else if(!keyword.compare("bounce_to"))
        {
            std::string tmp = "";
            while (data_stream >> keyword && keyword != "}")
                tmp += " " + keyword;
            tmpval = ld->add_option_to_table("--bounce_to", tmp + "}");
        }

        else
        {
            tmpval = false;
        }

        if (retval && !tmpval)
            retval = false;
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
    Telnet(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Telnet() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool Telnet::convert(std::istringstream& data_stream)
{
    std::string keyword;
    int i_val;
    bool retval = true;

    ld->open_table("telnet");

    while(data_stream >> keyword)
    {
        bool tmpval = true;
        if(!keyword.compare("ayt_attack_thresh"))
        {
            if(data_stream >> i_val)
                tmpval = ld->add_option_to_table("ayt_attack_thresh", i_val);
            else
                tmpval = false;
        }

        else  if(!keyword.compare("normalize"))
            tmpval = ld->add_option_to_table("normalize", true);

        else  if(!keyword.compare("ports"))
        {
            ld->add_diff_option_comment("ports", "bindings");
            ld->add_comment_to_table("check bindings table for port information");
            // vvvv defined in ConversionState vvvv

            // add commented list for now
            std::string tmp = "";
            while (data_stream >> keyword && keyword != "}")
                tmp += " " + keyword;
            tmpval = ld->add_option_to_table("--ports", tmp + "}");


//            parse_curly_bracket_list("--ports", data_stream); // create a commented list of the ports
        }

        else if(!keyword.compare("detect_anomalies"))
            ld->add_deleted_comment("detect_anomalies");

        else
            tmpval = false;

        retval = tmpval && retval;
    }

    return retval;
}

/****************************************
 *******  FtpTelnetProtocol  ************
 ****************************************/

namespace {

class FtpTelnetProtocol : public ConversionState
{
public:
    FtpTelnetProtocol(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~FtpTelnetProtocol() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace


bool FtpTelnetProtocol::convert(std::istringstream& data_stream)
{
    std::string protocol;

    if(data_stream >> protocol)
    {
        if(!protocol.compare("telnet"))
        {
            cv->set_state(new Telnet(cv, ld));
        }
        else if (!protocol.compare("ftp"))
        {
            if(data_stream >> protocol)
            {
                if(!protocol.compare("client"))
                    cv->set_state(new FtpClient(cv, ld));

                else if (!protocol.compare("server"))
                    cv->set_state(new FtpServer(cv, ld));

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

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new FtpTelnetProtocol(cv, ld);
}

static const ConvertMap ftptelnet_protocol_preprocessor = 
{
    "ftp_telnet_protocol",
    ctor,
};

const ConvertMap* ftptelnet_protocol_map = &ftptelnet_protocol_preprocessor;

} // namespace preprocessors
