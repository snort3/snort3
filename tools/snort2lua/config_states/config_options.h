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
// config_options.h author Josh Rosenbaum <jorosenba@cisco.com>

#ifndef CONFIG_OPTIONS_H
#define CONFIG_OPTIONS_H


#include <string>
#include <sstream>
#include "conversion_state.h"
#include "util/converter.h"


class ConfigIntOption : public ConversionState
{
public:
    explicit ConfigIntOption(Converter* cv,
                            LuaData* ld,
                            std::string table_name,
                            std::string opt_name)
                            : ConversionState(cv, ld) 
    {
        this->table_name = table_name;
        this->opt_name = opt_name;
    };

    virtual ~ConfigIntOption() {};
    virtual bool convert(std::istringstream& stream)
    {
        ld->open_table(table_name);
        return parse_int_option(opt_name, stream);
    }

private:
    std::string table_name;
    std::string opt_name;
};

/*  Parse a 'config' option which contain one and only one string value */
class ConfigStringOption : public ConversionState
{
public:
    explicit ConfigStringOption(Converter* cv,
                                LuaData* ld,
                                std::string table_name,
                                std::string opt_name)
                                : ConversionState(cv, ld) 
    {
        this->table_name = table_name;
        this->opt_name = opt_name;
    };

    virtual ~ConfigStringOption() {};
    virtual bool convert(std::istringstream& stream)
    {
        ld->open_table(table_name);
        return parse_string_option(opt_name, stream);
    }

private:
    std::string table_name;
    std::string opt_name;
};


/**********************************
 ********  TEMPLATES!!   **********
 **********************************/

template<const std::string *snort_option,
        const std::string *lua_table_name,
        const std::string* lua_option_name,
        bool (*parse_func)(std::string table_name, std::istringstream& stream)>
class ParseConfigOption : public ConversionState
{
public:
    ParseConfigOption( Converter* cv, LuaData* ld)
                            : ConversionState(cv, ld)
    {
    };

    virtual ~ParseConfigOption() {};
    virtual bool convert(std::istringstream& stream)
    {
        // if the two names are not equal ...
        if((*snort_option).compare((*lua_option_name)))
            ld->add_diff_option_comment(*snort_option, *lua_option_name);

        ld->open_table((*lua_table_name));
        return parse_func((*lua_option_name), stream);
    }
};


template<const std::string *snort_option,
        const std::string *lua_table_name,
        const std::string* lua_option_name>
class ConfigIntTempOption : public ConversionState
{
public:
    ConfigIntTempOption( Converter* cv, LuaData* ld)
                            : ConversionState(cv, ld)
    {
    };

    virtual ~ConfigIntTempOption() {};
    virtual bool convert(std::istringstream& stream)
    {
        // if the two names are not equal ...
        if((*snort_option).compare((*lua_option_name)))
            ld->add_diff_option_comment(*snort_option, *lua_option_name);

        ld->open_table((*lua_table_name));
        return parse_int_option(*lua_option_name, stream);
    }
};


template<const std::string *snort_option, const std::string *lua_name, const std::string *lua_option_name = nullptr>
static ConversionState* config_int_ctor(Converter* cv, LuaData* ld)
{
    if (lua_option_name)
        return new ConfigIntTempOption<snort_option, lua_name, lua_option_name>(cv, ld);
    else
        return new ConfigIntTempOption<snort_option, lua_name, snort_option>(cv, ld);
}



#endif
