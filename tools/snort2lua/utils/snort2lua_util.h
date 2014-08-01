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
// util.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef UTIL_H
#define UTIL_H


#include <string>
#include <vector>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>
#include <sstream>

struct ConvertMap;

namespace util
{

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);
const ConvertMap* find_map(const std::vector<const ConvertMap*>, std::string keyword);

// trim from begining
std::string &ltrim(std::string &s);
// trim from end
std::string &rtrim(std::string &s);
// trim from both ends
std::string &trim(std::string &s);


// trim from start
inline std::string &ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
        return s;
}

// trim from end
inline std::string &rtrim(std::string &s) {
        s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
        return s;
}

// trim from both ends
inline std::string &trim(std::string &s) {
        return ltrim(rtrim(s));
}


// return true if this file exists. False otherwise.
bool file_exists (const std::string& name);

/* Takes in a stream and a string of delimeters. The function will extract the charachters
 * from the stream until it hits one of the delimeters.  The substring will be set to the
 * third parameter.  The stream itself will point to the chrachter after the first delim.
 *
 * PARAMS:
 *          data_stream - the data stream from which to find a substring.
 *          delimeters - The string of delimeters.
 *          options - The found substring will be place in this parameter.  If the
 *                     stream is empty or no charachters have been extracted, then
 *                     this parameter wil be set to an empty string.
 * RETURNS:
 *          True - when the string is found.
 *          False - whenma substing was unable to be extracted.
 */
bool get_string(std::istringstream& data_stream, std::string& option,
        const std::string delimeters);


std::string get_rule_option_args(std::istringstream& data_stream);

// remove any ']]' and double spaces from this string.
std::string &sanitize_lua_string(std::string &s);

// find the location of the first space before max_str_lenght.
// if no space exists before max_str_length, return the first space
// after max_length. Otherwise, return std::string::npos
std::size_t  get_substr_length(std::string s, std::size_t max_length);

bool case_compare(std::string, std::string);

}  // namespace util

#endif
