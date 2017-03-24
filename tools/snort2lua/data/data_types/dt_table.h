//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// dt_table.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DATA_DATA_TYPES_DT_TABLE_H
#define DATA_DATA_TYPES_DT_TABLE_H

#include <string>
#include <vector>
#include <iostream>

class Option;
class Variable;
class Comments;

class Table
{
public:
    Table(int depth);
    Table(std::string name, int depth);
    virtual ~Table();

    inline std::string get_name() { return name; }
    bool has_differences();
    Table* open_table();
    Table* open_table(std::string);
    bool add_option(std::string val);
    bool add_option(std::string, int val);
    bool add_option(std::string, bool val);
    bool add_option(std::string, std::string val);
    bool add_list(std::string, std::string next_elem);
    void add_comment(std::string comment);
    bool has_option(const std::string);
    bool get_option(const std::string opt_name, std::string& value);

    /*  emit options after table has finished printing.
        These options will be appended to the previous table as supposed
        to overwriting the entire table */
    void append_option(std::string opt_name, int val);
    void append_option(std::string opt_name, bool val);
    void append_option(std::string opt_name, std::string val);

    friend std::ostream& operator<<(std::ostream&, const Table&);

private:
    std::string name;
    int depth;
    Comments* comments;
    std::vector<Table*> tables;
    std::vector<Option*> options;
    std::vector<Variable*> lists;
    std::vector<Option*> append_options;

    bool has_option(std::string name, int val);
    bool has_option(std::string name, bool val);
    bool has_option(std::string name, std::string val);
    bool has_option(Option o);
};

#endif

