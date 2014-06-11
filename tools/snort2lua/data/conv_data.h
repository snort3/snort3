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
// conversion_data.h author Josh Rosenbaum <jorosenba@cisco.com>

#ifndef CONV_DATA_H
#define CONV_DATA_H

#include <string>
#include <iostream>
#include <vector>

#include "data/conv_table.h"
#include "data/conv_var.h"

class ConversionData
{

public:
    ConversionData();
    virtual ~ConversionData();

    friend std::ostream &operator<<( std::ostream&, const ConversionData &);
    bool add_variable(std::string name, std::string value);
    Table* add_table(std::string name);

#if 0
    bool add_option(std::string name, std::string value);
    bool add_option(std::string name, long long int value);
    void reset();
#endif

private:
    std::vector<Variable*> vars;
    std::vector<Table*> tables;

};


#endif
