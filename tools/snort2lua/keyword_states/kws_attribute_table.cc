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
#include <unordered_map>

#include "conversion_state.h"
#include "utils/s2l_util.h"
#include "tinyxml/tinyxml.h"

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
    std::istringstream* stream; // tempporarily a variable so I can hit failed_conversion
    std::unordered_map<std::string, std::string> attr_map;

    std::string add_lua_opt(TiXmlNode* node, std::string lua_opt = std::string());
    bool parse_map_entries(TiXmlNode* snort_attr);
    bool parse_attr_table(TiXmlNode* snort_attr);
    bool parse_entry(TiXmlNode* mapped_entry);
    bool parse_host(TiXmlNode* host);
    bool parse_service(TiXmlNode* host);
};

} // namespace


/*
 * Add this Node's Child's text as a lua options.  This
 * returns void since it will automatically add a
 * bad opiton to the reject's file.
 *
 * ASSUMPTION: The relevant table has already been opened
 */
std::string AttributeTable::add_lua_opt(TiXmlNode* node, std::string lua_opt)
{
    TiXmlNode* text_node = node->LastChild();

    if (!text_node)
    {
        ld->developer_error("Attribute Table::add_lua_opt() --> " +
            std::string(node->Value()) + " has no child!!");
    }
    else
    {
        std::string text_str(text_node->Value());

        if (text_str.empty())
            ld->developer_error("Attribute Table::add_lua_opt() --> " +
                std::string(node->Value()) + " child has no Text!");
        else
        {
            if (!lua_opt.empty())
                ld->add_option_to_table(lua_opt, text_str);
            return text_str;
        }
    }

    return std::string();
}

/*
 * The element passed in should be an ENTRY node
 */
bool AttributeTable::parse_entry(TiXmlNode* mapped_entry)
{

    if (std::string(mapped_entry->Value()).compare("ENTRY"))
        return false;

    TiXmlNode* elem_id = mapped_entry->LastChild("ID");
    TiXmlNode* elem_value = mapped_entry->LastChild("VALUE");

    if (!elem_id || !elem_value)
        return false;

    TiXmlNode* id_text =  elem_id->LastChild();
    TiXmlNode* value_text =  elem_value->LastChild();

    if (!id_text || !value_text)
        return false;

    std::string id = std::string(id_text->Value());
    std::string val = std::string(value_text->Value());

    attr_map[id] = val;
    return true;
}

/*
 * Parse the 'SERVICE' element and add elemnts to Lua configuration
 */
bool AttributeTable::parse_service(TiXmlNode* service)
{
    if (std::string(service->Value()).compare("SERVICE"))
        return false;

    ld->open_table("services");
    ld->open_table();

    TiXmlNode* name = service->LastChild("PROTOCOL");
    if (name)
    {
        TiXmlNode* val = name->LastChild("ATTRIBUTE_VALUE");
        if (val)
        {
            std::string val_str = add_lua_opt(val);
            ld->add_option_to_table("name", val_str);
        }

        TiXmlNode* id = name->LastChild("ATTRIBUTE_ID");
        if (id)
        {
            std::string id_str = add_lua_opt(id);
            ld->add_option_to_table("name", attr_map[id_str]);
        }
    }

    TiXmlNode* proto = service->LastChild("IPPROTO");
    if (proto)
    {
        TiXmlNode* val = proto->LastChild("ATTRIBUTE_VALUE");
        if (val)
        {
            std::string proto_str = add_lua_opt(val);
            ld->add_option_to_table("proto", proto_str);
        }

        TiXmlNode* id = proto->LastChild("ATTRIBUTE_ID");
        if (id)
        {
            std::string proto_str = add_lua_opt(id);
            ld->add_option_to_table("proto", attr_map[proto_str])   ;
        }
    }

    TiXmlNode* port =  service->LastChild("PORT");
    if (port)
    {
        TiXmlNode* val = port->LastChild("ATTRIBUTE_VALUE");
        if (val)
        {
            int port = std::stoi(add_lua_opt(val));
            ld->add_option_to_table("proto", port);
        }

        TiXmlNode* id = port->LastChild("ATTRIBUTE_ID");
        if (id)
        {
            std::string proto_str = add_lua_opt(id);
            ld->add_option_to_table("proto", std::stoi(attr_map[proto_str]));
        }
    }

    ld->close_table();
    ld->close_table();
    return true;
}

/*
 * Parse the 'HOST' element and add elemnts to Lua configuration
 */
bool AttributeTable::parse_host(TiXmlNode* host)
{
    bool retval = true;

    if (std::string(host->Value()).compare("HOST"))
        return false;

    ld->open_table("hosts");
    ld->add_diff_option_comment("Attribute_table: STREAM_POLICY", "hosts: tcp_policy");
    ld->open_table();

    // First up, the IP
    TiXmlNode* ip = host->LastChild("IP");
    if (ip)
        add_lua_opt(ip, "ip");

    TiXmlNode* os = host->LastChild("OPERATING_SYSTEM");
    if (os)
    {
        TiXmlNode* frag_policy = os->LastChild("FRAG_POLICY");
        if (frag_policy)
        {
            std::string policy = add_lua_opt(frag_policy);

            if (!policy.compare("unknown"))
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
                retval = false;
                ld->failed_conversion(*stream, "Attribute_Table: <FRAG_POLICY>" +
                    policy + "</FRAG_POLICY>");
            }
        }


        TiXmlNode* tcp_policy = os->LastChild("STREAM_POLICY");
        if (tcp_policy)
        {
            std::string policy = add_lua_opt(tcp_policy);

            if (!policy.compare("bsd"))
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
                retval = false;
                ld->failed_conversion(*stream, policy);
            }
        }
    }

    TiXmlNode* services = host->LastChild("SERVICES");
    if (services)
    {
        for ( TiXmlNode* elem = services->FirstChild();
                elem != 0; elem = elem->NextSibling())
        {
            parse_service(elem);
        }
    }


    ld->close_table();
    ld->close_table();
    return retval;
}

/*
 * Expected the Parameter passed in to be a pointer to
 * the ATTRIBUTE_MAP node
 */
bool AttributeTable::parse_map_entries(TiXmlNode* snort_attr)
{
    bool retval = true;
    TiXmlNode* map = snort_attr->FirstChild("ATTRIBUTE_MAP");

    for ( TiXmlNode* elem = map->FirstChild(); elem != 0; elem = elem->NextSibling())
    {
        if (!parse_entry(elem))
            retval = false;
    }

    snort_attr->RemoveChild(map);
    return retval;
}

bool AttributeTable::parse_attr_table(TiXmlNode* snort_attr)
{
    bool retval = true;

    TiXmlNode* attr_table = snort_attr->FirstChild("ATTRIBUTE_TABLE");

    for ( TiXmlNode* elem = attr_table->FirstChild(); elem != 0; elem = elem->NextSibling())
    {
        if (!parse_host(elem))
            retval = false;
    }

    return retval;
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


    stream = &data_stream;

    file = ld->expand_vars(file);
    TiXmlDocument doc(file.c_str());


    if (!util::file_exists(file) || !doc.LoadFile()) // really the same test twice
    {
        ld->open_table("hosts");
        ld->add_comment_to_table("unable to open the attribute file: " + file);
        return false;
    }

    // Now that we have parsed the config option and loaded the file,
    // begin converting to Snort++ format.


    TiXmlNode* attributes = doc.FirstChild("SNORT_ATTRIBUTES");

    parse_map_entries(attributes); // save all mapped items to attr_map
    parse_attr_table(attributes); // parse and converter remaining xml document
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
