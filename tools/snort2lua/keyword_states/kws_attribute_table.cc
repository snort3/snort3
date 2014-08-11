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
// kws_attribute_tables.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <fstream>
#include <unordered_map>

#include "conversion_state.h"
#include "utils/s2l_util.h"


namespace keywords
{

namespace {

class AttributeTable : public ConversionState
{
public:
    AttributeTable(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~AttributeTable() {};
    virtual bool convert(std::istringstream& data);

private:
    std::istringstream* stream; // so I can caldd ld->failed_conversion
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
        // add the '<' charachter back for next call
        attr_file.unget();
        return true;
    }

    // since we've already extracted everything until '<'
    std::getline(attr_file, elem, '>');

    util::trim(elem);
    return !elem.empty();
}

/*
 * Parse the 'SERVICE' element and add elemnts to Lua configuration
 */
void AttributeTable::parse_service()
{
    std::string elem;

    ld->open_table("services");
    ld->open_table();

    while(get_next_element(elem) &&
          elem.compare("/SERVICE"))
    {
        if (!elem.compare("PROTOCOL"))
        {
            while(get_next_element(elem) &&
                elem.compare("/PROTOCOL"))
            {
                if (!elem.compare("ATTRIBUTE_VALUE"))
                {
                    get_next_element(elem);
                    ld->add_option_to_table("name", elem);
                }
                else if (!elem.compare("ATTRIBUTE_ID"))
                {
                    get_next_element(elem);
                    ld->add_option_to_table("name", attr_map[elem]);
                }
            } // while("/PROTOCOL")
        }
        else if (!elem.compare("IPPROTO"))
        {
            while(get_next_element(elem) &&
                elem.compare("/IPPROTO"))
            {
                if (!elem.compare("ATTRIBUTE_VALUE"))
                {
                    get_next_element(elem);
                    ld->add_option_to_table("proto", elem);
                }
                else if (!elem.compare("ATTRIBUTE_ID"))
                {
                    get_next_element(elem);
                    ld->add_option_to_table("proto", attr_map[elem]);
                }
            } // while("/IPPROTO")
        }
        else if (!elem.compare("PORT"))
        {
            while(get_next_element(elem) &&
                elem.compare("/PORT"))
            {
                if (!elem.compare("ATTRIBUTE_VALUE"))
                {
                    get_next_element(elem);
                    ld->add_option_to_table("proto", std::stoi(elem));
                }
                else if (!elem.compare("ATTRIBUTE_ID"))
                {
                    get_next_element(elem);
                    ld->add_option_to_table("proto", std::stoi(attr_map[elem]));
                }
            } // while("/IPPROTO")
        }
    } // while ("/SERVICE")

    ld->close_table();
    ld->close_table();
}


/*
 * Parse the 'SERVICES' element.  Expect 'SERVICE'
 */
void AttributeTable::parse_services()
{
    std::string elem;

    while(get_next_element(elem) &&
          elem.compare("/SERVICES"))
    {
        // every element in an attribute table should be a host
        if (!elem.compare("SERVICE"))
            parse_service();
        else
            ld->failed_conversion(*stream, "AttributeTable: <SERVICES>"
                                  " should only contain <SERVICE> elements!");
    }
}

void AttributeTable::parse_os()
{
    std::string elem;

    while(get_next_element(elem) &&
          elem.compare("/OPERATING_SYSTEM"))
    {

        if (!elem.compare("FRAG_POLICY"))
        {
            std::string policy;

            if (!get_next_element(policy))
                ld->failed_conversion(*stream,  "AttributeTable:"
                    " <FRAG_POLICY>**missing policy**</FRAG_POLICY>");

            else if (!policy.compare("unknown"))
                    ld->add_deleted_comment("Attribute_table: <FRAG_POLICY>unkown</FRAG_POLICY>");

            else if (!policy.compare("hpux"))
                ld->add_deleted_comment("Attribute_table: <FRAG_POLICY>hpux</FRAG_POLICY>");

            else if (!policy.compare("irix"))
                ld->add_deleted_comment("Attribute_table: <FRAG_POLICY>irix</FRAG_POLICY>");

            else if (!policy.compare("old-linux"))
                ld->add_deleted_comment("Attribute_table: <FRAG_POLICY>old-linux</FRAG_POLICY>");

            else if (!policy.compare("bsd"))
                ld->add_option_to_table("frag_policy", "bsd");

            else if (!policy.compare("first"))
                ld->add_option_to_table("frag_policy", "first");

            else if (!policy.compare("last"))
                ld->add_option_to_table("frag_policy", "last");

            else if (!policy.compare("linux"))
                ld->add_option_to_table("frag_policy", "linux");

            else if (!policy.compare("solaris"))
                ld->add_option_to_table("frag_policy", "solaris");

            else if (!policy.compare("windows"))
                ld->add_option_to_table("frag_policy", "windows");

            else if (!policy.compare("bsd-right"))
            {
                // keep this on one line so data miner can find it
                ld->add_diff_option_comment("Attribute_table: <FRAG_POLICY>bsd-right</FRAG_POLICY>", "hosts.frag_policy = bsd_right");
                ld->add_option_to_table("frag_policy", "bsd_right");
            }

            else
            {
                ld->failed_conversion(*stream, "Attribute_Table: <FRAG_POLICY>" +
                    policy + "</FRAG_POLICY>");
            }
        }

        else if (!elem.compare("STREAM_POLICY"))
        {
            std::string policy;


            if (!get_next_element(policy))
                ld->failed_conversion(*stream,  "AttributeTable:"
                    " <STREAM_POLICY>**missing policy**</STREAM_POLICY>");

            else if (!policy.compare("bsd"))
                    ld->add_option_to_table("tcp_policy", "bsd");

            else if (!policy.compare("first"))
                ld->add_option_to_table("tcp_policy", "first");

            else if (!policy.compare("irix"))
                ld->add_option_to_table("tcp_policy", "irix");

            else if (!policy.compare("last"))
                ld->add_option_to_table("tcp_policy", "last");

            else if (!policy.compare("linux"))
                ld->add_option_to_table("tcp_policy", "linux");

            else if (!policy.compare("macos"))
                ld->add_option_to_table("tcp_policy", "macos");

            else if (!policy.compare("old-linux"))
                ld->add_option_to_table("tcp_policy", "old-linux");

            else if (!policy.compare("solaris"))
                ld->add_option_to_table("tcp_policy", "solaris");

            else if (!policy.compare("windows"))
                ld->add_option_to_table("tcp_policy", "windows");

            else if (!policy.compare("win-2003"))
                ld->add_option_to_table("tcp_policy", "win-2003");

            else if (!policy.compare("vista"))
                ld->add_option_to_table("tcp_policy", "vista");

            else if (!policy.compare("unknown"))
                ld->add_deleted_comment("Attribute_table: <FRAG_POLICY>unkown</FRAG_POLICY>");

            else if (!policy.compare("hpux"))
            {
                ld->add_diff_option_comment("Attribute_table: <FRAG_POLICY>hpux</FRAG_POLICY>", "hosts.tcp_policy = hpux10");
                ld->add_option_to_table("tcp_policy", "hpux10");
            }

            else if (!policy.compare("hpux11"))
            {
                ld->add_diff_option_comment("Attribute_table: <FRAG_POLICY>hpux11</FRAG_POLICY>", "hosts.tcp_policy = hpux");
                ld->add_option_to_table("tcp_policy", "hpux");
            }

            else
            {
                ld->failed_conversion(*stream, "Attribute_Table: <STREAM_POLICY>" +
                    policy + "</STREAM_POLICY>");                }
        }
    }
}


/*
 * Parse the 'HOST' element and add elements to Lua configuration
 */
void AttributeTable::parse_host()
{
    ld->open_table("hosts");
    ld->add_diff_option_comment("Attribute_table: STREAM_POLICY", "hosts: tcp_policy");
    ld->open_table();

    std::string elem;


    while(get_next_element(elem) &&
          elem.compare("/HOST"))
    {
        if (!elem.compare("OPERATING_SYSTEM"))
        {
            parse_os();
        }
        else if (!elem.compare("SERVICES"))
        {
            parse_services();
        }
        else if (!elem.compare("IP"))
        {
            std::string ip;
            if (get_next_element(ip))
                ld->add_option_to_table("ip", ip);
            else
                ld->failed_conversion(*stream,  "AttributeTable:"
                    " <IP>**missing ip**</IP>");
        }
    }

    ld->close_table();
    ld->close_table();
}

void AttributeTable::parse_attr_table()
{
    std::string elem;

    while(get_next_element(elem) &&
          elem.compare("/ATTRIBUTE_TABLE"))
    {
        // every element in an attribute table should be a host
        if (elem.compare("HOST"))
            ld->failed_conversion(*stream, "AttributeTable: <ATTRIBUTE_TABLE>"
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

    while(get_next_element(elem) &&
          elem.compare("/ENTRY"))
    {
        if (!elem.compare("ID"))
        {
            if (!get_next_element(id))
                ld->failed_conversion(*stream, "AttributeTable:"
                    " <ID>**missing option**</ID>");
        }
        else if (!elem.compare("VALUE"))
        {
            if (!get_next_element(value))
                ld->failed_conversion(*stream, "AttributeTable:"
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

    while(get_next_element(elem) &&
          elem.compare("/ATTRIBUTE_MAP"))
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

    if (file.compare("filename"))
        return false;

    if (!(data_stream >> file))
        return false;

    if (file.empty())
        return false;

    // setting class variables
    stream = &data_stream;
    file = ld->expand_vars(file);


    if (!util::file_exists(file))
    {
        ld->open_table("hosts");
        ld->add_comment_to_table("unable to open the attribute file: " + file);
        return false;
    }

    attr_file.open(file, std::ifstream::in);
    std::string elem;
    while (get_next_element(elem))
    {
        if (!elem.compare("ATTRIBUTE_MAP"))
            parse_map_entries();

        else if (!elem.compare("ATTRIBUTE_TABLE"))
            parse_attr_table();

        /*
         * While there probaby should be another else,
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

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new AttributeTable(cv, ld);
}

static const ConvertMap attribute_table_api =
{
    "attribute_table",
    ctor,
};

const ConvertMap* attribute_table_map = &attribute_table_api;

}  // namespace keywords
