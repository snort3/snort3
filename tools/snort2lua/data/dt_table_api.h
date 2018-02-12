//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// dt_table_api.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DATA_DT_TABLE_API_H
#define DATA_DT_TABLE_API_H

#include <functional>
#include <iostream>
#include <queue>
#include <stack>
#include <string>
#include <unordered_map>
#include <vector>

/*
*
* As a heads up to whoever reads this file.  This one API is
* really three distinct API's rolled into one.  One API for rules,
* one api for misc data (variables, includes, etcs), one api
* for creating tables. However, the reason they are
* together is because this class is not static, and I did not
* want to be pass three pointers to the three API's when
* creating new conversion states.  There are comments in
* in all caps which show the separate the sections.
*
* The first section of this file is really DataApi creation
* and initialization, and adding miscellaneous objects
* to the DataApi data.  The second section is for creating
* tables and their options.  The third section is for
* creating rules.
*/
// dt_table_api.h author Josh Rosenbaum <jrosenba@cisco.com>

class Table;
class TableApi;

typedef std::unordered_map<std::string, bool> TableDelegation;
typedef std::function<void(TableApi&)> PendingFunction;

class TableApi
{
public:
    TableApi() = default;
    TableApi(TableApi* d, TableDelegation& td) : delegate(d), delegations(td) {}
    virtual ~TableApi();

    void reset_state();
    friend std::ostream& operator<<(std::ostream& out, const TableApi& table);
    void print_tables(std::ostream& out) const;

    inline bool empty() const
    { return tables.empty(); }

/*
 * Accessing and choosing specific tables.
 */

// open a table at the topmost layer. i.e., the table will not be nested inside any other table.
    void open_top_level_table(const char* name, bool one_line = false)
    { open_top_level_table(std::string(name), one_line); }

    void open_top_level_table(const std::string& name, bool one_line = false);

// open a nested named table --> 'name = {...}')
    void open_table(const std::string& name, bool one_line = false);

    void open_table(const char* name, bool one_line = false)
    { open_table(std::string(name), one_line); }

// open a nested table that does not contain a name --> {...})
    void open_table(bool one_line = false);

// close the nested table.  go to previous table level
    void close_table();

    void swap_tables(std::vector<Table*>& new_tables);

/*
 * Adding/accessing data to the specific table chosen above!!
 * These methods will all throw a developer warning if called without
 * selecting a table!
 */

/*
 * add a string, bool, or int option to the table. --> table = { name = var |'var'};
 * NOTE:  if val is a string/char* and starts with a '$', Snort2lua assumes that val
 *        is a Snort/Lua variable. Therefore, if val starts with $, Snort2Lua will not
 *        place quotes around the string
 * The add_option variants without an option name are used to add "anonymous" options
 * for the purpose of creating arrays.
 */
    bool add_option(const std::string& val);
    bool add_option(const char* const v);
    bool add_option(const std::string& opt_name, const std::string& val);
    bool add_option(const std::string& opt_name, const int val);
    bool add_option(const std::string& opt_name, const bool val);
    bool add_option(const std::string& opt_name, const char* const v);

// sometimes, you may need to create a default option, before overwriting that
// option later. For instance, if you have a default table, and then you
// need to overwrite a single option in that default table, you can use these
// methods to overwrite that option.
    void append_option(const std::string& opt_name, const std::string& val);
    void append_option(const std::string& opt_name, const int val);
    void append_option(const std::string& opt_name, const bool val);
    void append_option(const std::string& opt_name, const char* const v);

// add an option with a list of variables -->  table = { name = 'elem1 elem2 ...' }
// corresponds to Parameter::PT_MULTI
    bool add_list(const std::string& list_name, const std::string& next_elem);
// add a comment to be printed in the table --> table = { -- comment \n ... }
    bool add_comment(const std::string& comment);
// add a comment about an option change to the table
    bool add_diff_option_comment(const std::string& orig_var, const std::string& new_var);
// attach a deprecated option comment to the current table
    bool add_deleted_comment(const std::string& dep_var);
// attach an unsupported option comment to the current table
    bool add_unsupported_comment(const std::string& unsupported_var);

// return true if this name exists as an option name for the selected table
    bool option_exists(const std::string& name);
// return true if this name exists as an option name for the selected table
// and value updated successfully
    bool get_option_value(const std::string& name, std::string& value);

    // allows adding options to tables if they exist or once they are created
    void run_when_exists(const char* table_name, PendingFunction action);

private:
    template<typename T>
    bool do_add_option(const std::string& opt_name, const T val, const std::string& s_val);

    template<typename T> 
    void do_append_option(const std::string& opt_name, const T val, const std::string& s_val);

    void create_append_data(std::string& fqn, Table*& t);
    bool should_delegate() const;
    bool should_delegate(const std::string& table_name) const;

// Data
    std::vector<Table*> tables;
    std::stack<Table*> open_tables;
    std::stack<unsigned> top_level_tables;
    std::unordered_map<std::string, std::queue<PendingFunction>> pending;
    bool curr_data_bad = false;

    TableApi* delegate = nullptr;
    TableDelegation delegations;
    unsigned delegating = 0; // Treat as stack position
};

#endif

