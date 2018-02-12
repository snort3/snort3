//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// s2l_util.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef HELPERS_UTIL_H
#define HELPERS_UTIL_H

#include <memory>
#include <string>
#include <vector>

struct ConvertMap;
class Table;

namespace util
{
std::vector<std::string>& split(const std::string& s, char delim, std::vector<std::string>& elems);

// Search through the vector for the map which matches keyword

Table* find_table(const std::vector<Table*>& vec, const std::string& name);
const ConvertMap* find_map(const std::vector<const ConvertMap*>&, const std::string& keyword, bool strict_case = true);
const std::unique_ptr<const ConvertMap>& find_map(
    const std::vector<std::unique_ptr<const ConvertMap> >&, const std::string& keyword, bool strict_case = true);

// trim from beginning
std::string& ltrim(std::string& s);

// trim from end
std::string& rtrim(std::string& s);

// trim from both ends
std::string& trim(std::string& s);

// trim single or double quotes from the beginning and end of string.
// Only removes quotes if they're the first and last character.
// "words in quotes" => words in quotes
// 'words in quotes' => words in quotes
// "quotes in "'string'"" => quotes in "'string'"
std::string& trim_quotes(std::string& s);

// return true if this file exists. False otherwise.
bool file_exists(const std::string& name);

/*
 * Takes in a stream and a string of delimiters. The function will extract the characters
 * from the stream until it hits one of the delimiters.  The substring will be set to the
 * third parameter.  The stream itself will point to the character after the first delim.
 *
 * PARAMS:
 *          data_stream - the data stream from which to find a substring.
 *          delimiters - The string of delimiters.
 *          options - The found substring will be place in this parameter.  If the
 *                     stream is empty or no characters have been extracted, then
 *                     this parameter will be set to an empty string.
 * RETURNS:
 *          True - when the string is found.
 *          False - when the substring was unable to be extracted.
 */
bool get_string(std::istringstream& data_stream,
    std::string& option,
    const std::string& delimiters);

/*
 * Returns the rest of the data_streams data as one argument.
 * Useful when parsing filenames with spaces or other
 * characters which can get removed by c++ libraries
 *
 * NO SIDE EFFECTS
 */
std::string get_remain_data(std::istringstream& data_stream);

std::string get_rule_option_args(std::istringstream& data_stream);

/*
 * When converting rules, some options require information from
 * a different options.  For instance, the rule options 'threshold'
 * needs to know both the rule's gid and sid.  This function
 * provides a simple way to get those values.
 *
 * PARAMS:
 *          data_stream - the rule's data stream
 *          opt_name - the option name for which to search.
 * RETURN:
 *          the opt_names value or an empty string if the opt_name
 *          is not found.
 *
 */
std::string rule_option_find_val(std::istringstream& data_stream,
    const std::string& opt_name);

// remove any ']]' and double spaces from this string.
std::string& sanitize_lua_string(std::string& s);

// find the location of the first space before max_str_length.
// if no space exists before max_str_length, return the first space
// after max_length. Otherwise, return std::string::npos
std::size_t get_substr_length(const std::string& s, std::size_t max_length);

bool case_compare(std::string, std::string);
bool is_regular_file(std::string& path);
}  // namespace util

#endif

