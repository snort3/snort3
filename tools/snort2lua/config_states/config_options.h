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
    virtual bool convert(std::stringstream& stream)
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
    virtual bool convert(std::stringstream& stream)
    {
        ld->open_table(table_name);
        return parse_string_option(opt_name, stream);
    }

private:
    std::string table_name;
    std::string opt_name;
};


#endif
