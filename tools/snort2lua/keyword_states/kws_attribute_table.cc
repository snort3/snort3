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
// kws_attribute_tables.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <fstream>
#include <unordered_map>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/parse_cmd_line.h"

namespace keywords
{
namespace
{
class AttributeTable : public ConversionState
{
public:
    AttributeTable(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;

private:
    std::istringstream* stream; // so I can call ld->failed_conversion
    std::unordered_map<std::string, std::string> attr_map;
    std::ifstream attr_file;

    bool get_next_element(std::string& elem);
    void parse_os();
    void parse_service();
    void parse_services();
    void parse_host();
    void parse_entry();
    void parse_map_entries();
    void parse_attr_table();
};
} // namespace

bool AttributeTable::get_next_element(std::string& elem)
{
    if (attr_file.eof())
        return false;

    std::getline(attr_file, elem, '<');
    util::trim(elem);

    if (!elem.empty() && elem.front() != '<')
    {
        // add the '<' character back for next call
        attr_file.unget();
        return true;
    }

    // since we've already extracted everything until '<'
    std::getline(attr_file, elem, '>');

    util::trim(elem);
    return !elem.empty();
}

/*
 * Parse the 'SERVICE' element and add elements to Lua configuration
 */
void AttributeTable::parse_service()
{
    std::string elem;

    table_api.open_table("services");
    table_api.open_table();

    while (get_next_element(elem) && elem != "/SERVICE")
    {
        if (elem == "PROTOCOL")
        {
            while (get_next_element(elem) && elem != "/PROTOCOL")
            {
                if (elem == "ATTRIBUTE_VALUE")
                {
                    get_next_element(elem);
                    table_api.add_option("name", elem);
                }
                else if (elem == "ATTRIBUTE_ID")
                {
                    get_next_element(elem);
                    table_api.add_option("name", attr_map[elem]);
                }
            } // while("/PROTOCOL")
        }
        else if (elem == "IPPROTO")
        {
            while (get_next_element(elem) && elem != "/IPPROTO")
            {
                if (elem == "ATTRIBUTE_VALUE")
                {
                    get_next_element(elem);
                    table_api.add_option("proto", elem);
                }
                else if (elem == "ATTRIBUTE_ID")
                {
                    get_next_element(elem);
                    table_api.add_option("proto", attr_map[elem]);
                }
            } // while("/IPPROTO")
        }
        else if (elem == "PORT")
        {
            while (get_next_element(elem) && elem != "/PORT")
            {
                if (elem == "ATTRIBUTE_VALUE")
                {
                    get_next_element(elem);
                    table_api.add_option("port", std::stoi(elem));
                }
                else if (elem == "ATTRIBUTE_ID")
                {
                    get_next_element(elem);
                    table_api.add_option("port", std::stoi(attr_map[elem]));
                }
            } // while("/IPPROTO")
        }
    } // while ("/SERVICE")

    table_api.close_table();
    table_api.close_table();
}

/*
 * Parse the 'SERVICES' element.  Expect 'SERVICE'
 */
void AttributeTable::parse_services()
{
    std::string elem;

    while (get_next_element(elem) && elem != "/SERVICES")
    {
        // every element in an attribute table should be a host
        if (elem == "SERVICE")
            parse_service();
        else
            data_api.failed_conversion(*stream, "AttributeTable: <SERVICES>"
                " should only contain <SERVICE> elements!");
    }
}

void AttributeTable::parse_os()
{
    std::string elem;

    while (get_next_element(elem) && elem != "/OPERATING_SYSTEM")
    {
        if (elem == "FRAG_POLICY")
        {
            std::string policy;

            if (!get_next_element(policy))
                data_api.failed_conversion(*stream,  "AttributeTable:"
                    " <FRAG_POLICY>**missing policy**</FRAG_POLICY>");

            else if (policy == "unknown")
                table_api.add_deleted_comment("<FRAG_POLICY>unknown</FRAG_POLICY>");

            else if (policy == "hpux")
                table_api.add_deleted_comment("<FRAG_POLICY>hpux</FRAG_POLICY>");

            else if (policy == "irix")
                table_api.add_deleted_comment("<FRAG_POLICY>irix</FRAG_POLICY>");

            else if (policy == "old-linux")
                table_api.add_deleted_comment("<FRAG_POLICY>old-linux</FRAG_POLICY>");

            else if (policy == "bsd")
                table_api.add_option("frag_policy", "bsd");

            else if (policy == "first")
                table_api.add_option("frag_policy", "first");

            else if (policy == "last")
                table_api.add_option("frag_policy", "last");

            else if (policy == "linux")
                table_api.add_option("frag_policy", "linux");

            else if (policy == "solaris")
                table_api.add_option("frag_policy", "solaris");

            else if (policy == "windows")
                table_api.add_option("frag_policy", "windows");

            else if (policy == "bsd-right")
            {
                // keep this on one line so data miner can find it
                table_api.add_diff_option_comment("<FRAG_POLICY>bsd-right</FRAG_POLICY>",
                    "hosts.frag_policy = bsd_right");
                table_api.add_option("frag_policy", "bsd_right");
            }
            else
            {
                data_api.failed_conversion(*stream, "<FRAG_POLICY>" +
                    policy + "</FRAG_POLICY>");
            }
        }
        else if (elem == "STREAM_POLICY")
        {
            std::string policy;

            if (!get_next_element(policy))
                data_api.failed_conversion(*stream,  "AttributeTable:"
                    " <STREAM_POLICY>**missing policy**</STREAM_POLICY>");

            else if (policy == "bsd")
                table_api.add_option("tcp_policy", "bsd");

            else if (policy == "first")
                table_api.add_option("tcp_policy", "first");

            else if (policy == "irix")
                table_api.add_option("tcp_policy", "irix");

            else if (policy == "last")
                table_api.add_option("tcp_policy", "last");

            else if (policy == "linux")
                table_api.add_option("tcp_policy", "linux");

            else if (policy == "macos")
                table_api.add_option("tcp_policy", "macos");

            else if (policy == "old-linux")
            {
                table_api.add_diff_option_comment("<STREAM_POLICY>old-linux</STREAM_POLICY>",
                    "hosts.tcp_policy = old_linux");
                table_api.add_option("tcp_policy", "old_linux");
            }
            else if (policy == "solaris")
                table_api.add_option("tcp_policy", "solaris");

            else if (policy == "windows")
                table_api.add_option("tcp_policy", "windows");

            else if (policy == "win-2003")
            {
                table_api.add_diff_option_comment("<STREAM_POLICY>win-2003</STREAM_POLICY>",
                    "hosts.tcp_policy = win_2003");
                table_api.add_option("tcp_policy", "win_2003");
            }
            else if (policy == "vista")
                table_api.add_option("tcp_policy", "vista");

            else if (policy == "hpux10")
                table_api.add_option("tcp_policy", "hpux10");

            else if (policy == "hpux")
            {
                table_api.add_diff_option_comment("<STREAM_POLICY>hpux</STREAM_POLICY>",
                    "hosts.tcp_policy = hpux11");
                table_api.add_option("tcp_policy", "hpux11");
            }

            else if (policy == "unknown")
                table_api.add_deleted_comment("<STREAM_POLICY>unknown</STREAM_POLICY>");

            else if (policy == "noack")
                table_api.add_deleted_comment("<STREAM_POLICY>noack</STREAM_POLICY>");

            else if (policy == "hpux11")
                table_api.add_option("tcp_policy", "hpux11");

            else if (policy == "win2003")
            {
                table_api.add_diff_option_comment("<STREAM_POLICY>win2003</STREAM_POLICY>",
                    "hosts.tcp_policy = win_2003");
                table_api.add_option("tcp_policy", "win_2003");
            }
            else if (policy == "win2k3")
            {
                table_api.add_diff_option_comment("<STREAM_POLICY>win2k3</STREAM_POLICY>",
                    "hosts.tcp_policy = win_2003");
                table_api.add_option("tcp_policy", "win_2003");
            }
            else if (policy == "grannysmith")
            {
                table_api.add_diff_option_comment("<STREAM_POLICY>grannysmith</STREAM_POLICY>",
                    "hosts.tcp_policy = macos");
                table_api.add_option("tcp_policy", "macos");
            }
            else
            {
                data_api.failed_conversion(*stream, "<STREAM_POLICY>" +
                    policy + "</STREAM_POLICY>");
            }
        }
    }
}

/*
 * Parse the 'HOST' element and add elements to Lua configuration
 */
void AttributeTable::parse_host()
{
    table_api.open_table("hosts");
    table_api.add_diff_option_comment("STREAM_POLICY", "hosts: tcp_policy");
    table_api.open_table();

    std::string elem;

    while (get_next_element(elem) && elem != "/HOST")
    {
        if (elem == "OPERATING_SYSTEM")
        {
            parse_os();
        }
        else if (elem == "SERVICES")
        {
            parse_services();
        }
        else if (elem == "IP")
        {
            std::string ip;
            if (get_next_element(ip))
                table_api.add_option("ip", ip);
            else
                data_api.failed_conversion(*stream,  "AttributeTable:"
                    " <IP>**missing ip**</IP>");
        }
    }

    table_api.close_table();
    table_api.close_table();
}

void AttributeTable::parse_attr_table()
{
    std::string elem;

    while (get_next_element(elem) && elem != "/ATTRIBUTE_TABLE")
    {
        // every element in an attribute table should be a host
        if (elem != "HOST")
            data_api.failed_conversion(*stream, "AttributeTable: <ATTRIBUTE_TABLE>"
                " should only contain <HOST> elements!");
        else
            parse_host();
    }
}

/*
 * The element passed in should be an ENTRY node
 */
void AttributeTable::parse_entry()
{
    std::string elem;
    std::string id = std::string();
    std::string value = std::string();

    while (get_next_element(elem) && elem != "/ENTRY")
    {
        if (elem == "ID")
        {
            if (!get_next_element(id))
                data_api.failed_conversion(*stream, "AttributeTable:"
                    " <ID>**missing option**</ID>");
        }
        else if (elem == "VALUE")
        {
            if (!get_next_element(value))
                data_api.failed_conversion(*stream, "AttributeTable:"
                    " <VALUE>**missing option**</VALUE>");
        }
    }

    // add this pair to the map.
    if (!id.empty() && !value.empty())
        attr_map[id] = value;
}

void AttributeTable::parse_map_entries()
{
    std::string elem;

    while (get_next_element(elem) && elem != "/ATTRIBUTE_MAP")
    {
        parse_entry();
    }
}

bool AttributeTable::convert(std::istringstream& data_stream)
{
    std::string file;

    // extract && test the 'file' keyword followed by the actual file.
    if (!(data_stream >> file))
        return false;

    if (file != "filename")
        return false;

    if (!(data_stream >> file))
        return false;

    if (file.empty())
        return false;

    // setting class variables
    stream = &data_stream;
    file = data_api.expand_vars(file);

    if (!util::file_exists(file))
    {
        std::string full_file = parser::get_conf_dir() + file;

        if (!util::file_exists(full_file))
        {
            table_api.open_table("hosts");
            table_api.add_comment("unable to open the attribute file: " + file);
            table_api.close_table();

            std::string error_string = "Can't find file " + file + ".  "
                "  Searched locations: " + file + ",  " + full_file;
            data_api.failed_conversion(data_stream, error_string);
            return false;
        }
        file = full_file;
    }

    table_api.open_table("hosts");
    table_api.add_diff_option_comment("filename <file_name>", "hosts[]");
    table_api.close_table();

    attr_file.open(file, std::ifstream::in);
    std::string elem;
    while (get_next_element(elem))
    {
        if (elem == "ATTRIBUTE_MAP")
            parse_map_entries();

        else if (elem == "ATTRIBUTE_TABLE")
            parse_attr_table();

        /*
         * While there probably should be another else,
         * I have absolutely NO idea what correct
         * 'grammar' entails. So, in this case and all others
         * just ignore any extra data.
         */
    }
    return true;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new AttributeTable(c); }

static const ConvertMap attribute_table_api =
{
    "attribute_table",
    ctor,
};

const ConvertMap* attribute_table_map = &attribute_table_api;
}  // namespace keywords

