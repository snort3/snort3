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
// dt_table.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DT_TABLE_H
#define DT_TABLE_H


#include <string>
#include <vector>
#include <iostream>

#include "dt_option.h"
#include "dt_var.h"
#include "dt_comment.h"

class Table
{
public:
    Table(int depth);
    Table(std::string name, int depth);
    virtual ~Table();

    inline std::string get_name(){ return name; };
    Table* open_table();
    Table* open_table(std::string);
    bool add_option(std::string, int val);
    bool add_option(std::string, bool val);
    bool add_option(std::string, std::string val);
    bool add_list(std::string, std::string next_elem);
    void add_comment(std::string comment);

    friend std::ostream &operator<<( std::ostream&, const Table &);

private:
    std::string name;
    int depth;
    Comments* comments;
    std::vector<Table*> tables;
    std::vector<Option*> options;
    std::vector<Variable*> lists;


    bool has_option(std::string name, int val);
    bool has_option(std::string name, bool val);
    bool has_option(std::string name, std::string val);
    bool has_option(Option o);
};

#endif
