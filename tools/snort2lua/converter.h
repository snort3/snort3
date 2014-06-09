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

#ifndef CONVERTER_H
#define CONVERTER_H

#include <string>
#include <fstream>
#include <sstream>

class ConversionState;

class Converter
{

public:
    Converter(){}
    virtual ~Converter() {};
    void reset_state();
    bool convert_line(std::stringstream& data, bool last_line, std::ofstream& out);
    void set_state(ConversionState* c);

    void print_line(std::stringstream& in);
    void print_line(std::ostringstream& in);
    void print_line(std::string& in);
private:
    static ConversionState* state;

};



#endif
