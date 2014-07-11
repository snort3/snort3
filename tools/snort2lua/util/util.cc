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
// util.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>
#include <sys/stat.h>
#include "util/util.h"
#include "conversion_state.h"

namespace util
{


std::vector<std::string> &split(const std::string &s, 
                                char delim, 
                                std::vector<std::string> &elems)
{
    std::istringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
    {
        elems.push_back(item);
    }

    return elems;
}

const ConvertMap* find_map(const std::vector<const ConvertMap*> map, std::string keyword)
{
    for (const ConvertMap *p : map)
        if (p->keyword.compare(0, p->keyword.size(), keyword) == 0)
            return p;

    return nullptr;
}

std::string &sanitize_multi_line_string(std::string &s)
{

    int found = s.find("]]");
    while (found != std::string::npos)
    {
        s.insert(found + 1, " ");
        found = s.find("]]");
    }

    found = s.find("  ");
    while (found != std::string::npos)
    {
        s.erase(found, 1);
        found = s.find("  ");

    }
    return s;
}


int get_substr_length(std::string str, int max_length)
{
    int str_len;

    if (str.size() < max_length)
        return str.size();

    str_len = str.rfind(" ", max_length);

    if (str_len == std::string::npos)
    {
        str_len = str.find(" ");

        if (str_len == std::string::npos)
            return str.size();
    }
    return str_len;
}

bool get_string(std::istringstream& stream,
                std::string& option,
                std::string delimeters)
{
    if (delimeters.empty() || !stream.good())
    {
        option = std::string();
        return false;
    }
    else if (delimeters.size() == 1)
    {
        std::getline(stream, option, delimeters[0]);
        trim(option);
        return !option.empty();
    }
    else
    {
        int pos;
        option = std::string();

        while (stream.good() && option.empty())
        {
            pos = stream.tellg();
            std::getline(stream, option, delimeters[0]);
        }

        // check to ensure we got some data (and not a whitespace string)
        if(option.find_first_not_of(' ') == std::string::npos)
            return false;

        int first_delim = option.find_first_of(delimeters);
        if (first_delim != std::string::npos)
        {
            option = option.substr(0, first_delim);
            stream.seekg(pos + first_delim + 1); // + 1 to eat delimeter
        }

        trim(option);
        return true;
    }
}

std::string get_rule_option_args(std::istringstream& stream)
{
    std::string args = std::string();
    std::string tmp;

    do
    {
        std::getline(stream, tmp, ';');
        args += tmp + ";";

    } while (tmp.back() == '\\');

    // semicolon will be added when printing
    args.pop_back();
    trim(args);
    return args;
}

bool file_exists (const std::string& name) {
  struct stat buffer;
  return (stat (name.c_str(), &buffer) == 0);
}

#if 0
bool is_textfile_empty( const char* filename )
{
    string   s;
    ifstream f( filename, ios::binary );

    // Check for UTF-8 BOM
    if (f.peek() == 0xEF)
    {
        f.get();
        if (f.get() != 0xBB)
            return false;
        if (f.get() != 0xBF)
            return false;
    }

    // Scan every line of the file for non-whitespace characters
    while (getline( f, s ))
    {
        if (s.find_first_not_of(
                    " \t\n\v\f\r" // whitespace
                    "\0\xFE\xFF"  // non-printing (used in various Unicode encodings)
                    ) != string::npos)
            return false;
    }

    // If we get this far, then the file only contains whitespace
    // (or its size is zero)
    return true;
}
#endif

} // namespace util
