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
// pps_ftp_telnet_protocol.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"

namespace {

class FtpServer : public ConversionState
{
public:
    FtpServer(Converter* cv);
    virtual ~FtpServer() {};
    virtual bool convert(std::stringstream& data_stream);
private:
    bool parse_alt_max_cmd(std::stringstream& data_stream);
    bool parse_cmd_validity_cmd(std::stringstream& data_stream);
    static int ftpsever_binding_id;
};

class FtpClient : public ConversionState
{
public:
    FtpClient(Converter* cv) : ConversionState(cv) {};
    virtual ~FtpClient() {};
    virtual bool convert(std::stringstream& data_stream);
private:
    static int ftpclient_binding_id;
};

class Telnet : public ConversionState
{
public:
    Telnet(Converter* cv)  : ConversionState(cv) {};
    virtual ~Telnet() {};
    virtual bool convert(std::stringstream& data_stream);
};

class FtpTelnetProtocol : public ConversionState
{
public:
    FtpTelnetProtocol(Converter* cv)  : ConversionState(cv) {};
    virtual ~FtpTelnetProtocol() {};
    virtual bool convert(std::stringstream& data_stream);
};

} // namespace


/****************************************
 *******  FtpServer Protocol  ***********
 ****************************************/

int FtpServer::ftpsever_binding_id = 1;


FtpServer::FtpServer(Converter* cv)  : ConversionState(cv)
{}

bool FtpServer::parse_alt_max_cmd(std::stringstream& data_stream)
{
    int i_val;
    bool tmpval;

    if(!(data_stream >> i_val))
        return false;

    cv->open_table("alt_max_param");
    cv->open_table();
    cv->add_option_to_table("length", i_val);
    tmpval = parse_curly_bracket_list("commands", data_stream);
    cv->close_table();
    cv->close_table();
    return tmpval;
}

bool FtpServer::parse_cmd_validity_cmd(std::stringstream& data_stream)
{
    std::string val;
    std::string elem;
    bool tmpval;

    if(!(data_stream >> val))
        return false;

    if(!(data_stream >> elem) || (elem != "<"))
        return false;


    cv->open_table("cmd_validity");
    cv->open_table();
    tmpval = cv->add_option_to_table("command", val);
    tmpval = cv->add_list_to_table("format", elem) && tmpval;

    while((data_stream >> elem) && (elem != ">"))
        tmpval = cv->add_list_to_table("format", elem) && tmpval;

    cv->add_list_to_table("format", elem);
    cv->close_table(); // anonymouse table
    cv->close_table(); // "cmd_validity" table
    return tmpval;
}

bool FtpServer::convert(std::stringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    if (data_stream >> keyword)
    {
        if(!keyword.compare("default"))
            cv->open_table("ftp_server");
        else
        {
            cv->open_table("ftp_server_target_" + std::to_string(ftpsever_binding_id));
            ftpsever_binding_id++;
            cv->add_comment_to_table("Unable to create target based ftp configuration at this time!!!");
            retval = false;
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
            cv->add_option_to_table("print_cmds", true);

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
        
        else if(!keyword.compare("data_chan"))
        {
            cv->add_deprecated_comment("data_chan", "ignore_data_chan");
            tmpval = cv->add_option_to_table("ignore_data_chan", true);
        }

        else if (!keyword.compare("ports"))
        {
            cv->add_deprecated_comment("ports", "bindings");
            cv->add_comment_to_table("check bindings table for port information");
            // add commented list for now
            std::string tmp = "";
            while (data_stream >> keyword && keyword != "}")
                tmp += " " + keyword;
            tmpval = cv->add_option_to_table("--ports", tmp + "}");
        }

        else
        {
            tmpval = false;
        }

        retval = retval && tmpval;
    }
    return retval;
}

/****************************************
 *******  FtpClient Protocol  ***********
 ****************************************/

int FtpClient::ftpclient_binding_id = 1;

bool FtpClient::convert(std::stringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    if (data_stream >> keyword)
    {
        if(!keyword.compare("default"))
            cv->open_table("ftp_client");
        else
        {
            cv->open_table("ftp_client_target_" + std::to_string(ftpclient_binding_id));
            ftpclient_binding_id++;
            cv->add_comment_to_table("Unable to create target based ftp configuration at this time!!!");
            retval = false;
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
            tmpval = cv->add_option_to_table("--bounce_to", tmp + "}");
        }

        else
        {
            tmpval = false;
        }

        retval = retval && tmpval;
    }


    return retval;
}

/****************************************
 *********  Telnet Protocol  ************
 ****************************************/

bool Telnet::convert(std::stringstream& data_stream)
{
    std::string keyword;
    int i_val;
    bool retval = true;

    cv->open_table("telnet");

    while(data_stream >> keyword)
    {
        bool tmpval = true;
        if(!keyword.compare("ayt_attack_thresh"))
        {
            if(data_stream >> i_val)
                tmpval = cv->add_option_to_table("ayt_attack_thresh", i_val);
            else
                tmpval = false;
        }

        else  if(!keyword.compare("normalize"))
            tmpval = cv->add_option_to_table("normalize", true);

        else  if(!keyword.compare("ports"))
        {
            cv->add_deprecated_comment("ports", "bindings");
            cv->add_comment_to_table("check bindings table for port information");
            // vvvv defined in ConversionState vvvv
            parse_curly_bracket_list("--ports", data_stream); // create a commented list of the ports
        }

        else  if(!keyword.compare("detect_anomalies"))
            tmpval = cv->add_option_to_table("detect_anomalies", true);

        else
            tmpval = false;

        retval = tmpval && retval;
    }

    return retval;
}

/****************************************
 *******  FtpTelnetProtocol  ************
 ****************************************/


bool FtpTelnetProtocol::convert(std::stringstream& data_stream)
{
    std::string protocol;

    if(data_stream >> protocol)
    {
        if(!protocol.compare("telnet"))
        {
            cv->set_state(new Telnet(cv));
        }
        else if (!protocol.compare("ftp"))
        {
            if(data_stream >> protocol)
            {
                if(!protocol.compare("client"))
                    cv->set_state(new FtpClient(cv));

                else if (!protocol.compare("server"))
                    cv->set_state(new FtpServer(cv));

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

static ConversionState* ctor(Converter* cv)
{
    return new FtpTelnetProtocol(cv);
}

static const ConvertMap ftptelnet_protocol_preprocessor = 
{
    "ftp_telnet_protocol",
    ctor,
};

const ConvertMap* ftptelnet_protocol_map = &ftptelnet_protocol_preprocessor;
