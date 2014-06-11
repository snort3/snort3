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
// converter.h author Josh Rosenbaum <jorosenba@cisco.com>

#ifndef CONVERSION_STATE_H
#define CONVERSION_STATE_H

#include <string>
#include <fstream>
#include <sstream>

#include "converter.h"
 
class ConversionState
{

public:
    ConversionState(Converter *cv){ converter = cv; }
    virtual ~ConversionState() {};
    virtual bool convert(std::stringstream& data)=0;

protected:
    Converter* converter;

    inline bool add_int_option(std::string keyword, std::stringstream& stream)
    {
        int val;

        if(stream >> val)
        {
            converter->add_option_to_table(keyword, val);
            return true;
        }

        converter->add_comment_to_table("snort.conf missing argument for: " + keyword + " <int>");
        return false;
    }

private:

};


typedef ConversionState* (*conv_new_f)(Converter*);

struct ConvertMap
{
    std::string keyword;
    conv_new_f ctor;
};




#endif
