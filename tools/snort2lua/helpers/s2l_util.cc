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
// s2l_util.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "s2l_util.h"

#include <sys/stat.h>

#include <algorithm>

#include "conversion_state.h"
#include "data/data_types/dt_table.h"

namespace util
{
std::vector<std::string>& split(const std::string& s,
    char delim,
    std::vector<std::string>& elems)
{
    std::istringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
    {
        elems.push_back(item);
    }

    return elems;
}

const ConvertMap* find_map(
    const std::vector<const ConvertMap*>& map,
    const std::string& keyword,
    bool strict_case)
{
    for (const ConvertMap* p : map)
    {
        if (strict_case)
        {
            if (p->keyword.compare(0, p->keyword.size(), keyword) == 0)
                return p;
        }
        else
        {
            if (case_compare(p->keyword, keyword))
                return p;
        }
    }

    return nullptr;
}

const std::unique_ptr<const ConvertMap>& find_map(
    const std::vector<std::unique_ptr<const ConvertMap> >& map,
    const std::string& keyword,
    bool strict_case)
{
    for (auto& p : map)
    {
        if (strict_case)
        {
            if (p->keyword.compare(0, p->keyword.size(), keyword) == 0)
                return p;
        }
        else
        {
            if (case_compare(p->keyword, keyword))
                return p;
        }
    }

    static std::unique_ptr<const ConvertMap> np(nullptr);
    return np;
}

Table* find_table(const std::vector<Table*>& vec, const std::string& name)
{
    if (name.empty())
        return nullptr;

    for ( auto* t : vec)
        if (name == t->get_name())
            return t;

    return nullptr;
}

std::string& ltrim(std::string& s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(
        std::isspace))));
    return s;
}

std::string& rtrim(std::string& s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(
        std::isspace))).base(), s.end());
    return s;
}

std::string& trim(std::string& s)
{
    return ltrim(rtrim(s));
}

std::string& trim_quotes(std::string& s)
{
    if(s.length() < 2)
        return s;

    if((s.front() == '"' and s.back() == '"') or
       (s.front() == '\'' and s.back() == '\''))
    {
        s.erase(0,1);
        s.pop_back();
    }

    return s;
}

std::string& sanitize_lua_string(std::string& s)
{
    std::size_t found = s.find("]]");
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

std::size_t get_substr_length(const std::string& str, std::size_t max_length)
{
    std::size_t str_len;

    if (str.size() < max_length)
        return str.size();

    str_len = str.rfind(' ', max_length);

    if (str_len == std::string::npos)
    {
        str_len = str.find(' ');

        if (str_len == std::string::npos)
            return str.size();
    }
    return str_len;
}

bool get_string(std::istringstream& stream,
    std::string& option,
    const std::string& delimiters)
{
    if (delimiters.empty() || !stream.good())
    {
        option = std::string();
        return false;
    }
    else if (delimiters.size() == 1)
    {
        std::getline(stream, option, delimiters[0]);
        trim(option);
        return !option.empty();
    }
    else
    {
        std::streamoff pos = 0;
        option = std::string();

        // we don't want an empty string
        while (stream.good() && option.empty())
        {
            pos = stream.tellg();
            std::getline(stream, option, delimiters[0]);
        }

        // find the first non-delimiter character
        const std::size_t first_char = option.find_first_not_of(delimiters);

        // if there are no characters between a delimiter, empty string. return false
        if (first_char == std::string::npos)
            return false;

        // find the first delimiter after the first non-delimiter
        std::size_t first_delim = option.find_first_of(delimiters, first_char);

        if (first_delim == std::string::npos)
            first_delim = option.size();    // set value to take proper substr
        else
            stream.seekg((std::streamoff)(pos) + (std::streamoff)(first_delim) + 1);

        option = option.substr(first_char, first_delim - first_char);
        trim(option);
        return true;
    }
}

std::string get_remain_data(std::istringstream& stream)
{
    // get string length
    const std::streamoff pos = stream.tellg();
    stream.seekg(0, stream.end);
    const std::streamoff length = stream.tellg() - pos;
    stream.seekg(pos);

    // read argument
    char* arg_c = new char[length + 1];
    stream.read(arg_c, length);
    arg_c[length] = '\0';
    std::string arg_s(arg_c);
    delete[] arg_c;
    util::trim(arg_s);
    return arg_s;
}

std::string get_rule_option_args(std::istringstream& stream)
{
    std::string args = std::string();
    std::string tmp;

    do
    {
        std::getline(stream, tmp, ';');
        args += tmp + ";";
    }
    while (tmp.back() == '\\');

    // semicolon will be added when printing
    args.pop_back();
    trim(args);
    return args;
}

std::string rule_option_find_val(std::istringstream& data_stream,
    const std::string& opt_name)
{
    std::string rule_keyword;
    std::string val = std::string();
    const std::streamoff curr_pos = data_stream.tellg();

    if (curr_pos == -1)
        data_stream.clear();

    data_stream.seekg(0);
    std::getline(data_stream, rule_keyword, '(');
    std::streamoff tmp_pos = data_stream.tellg();

    // This loop is a near duplicate of set_next_rule_state.
    while (std::getline(data_stream, rule_keyword, ':'))
    {
        std::size_t semi_colon_pos = rule_keyword.find(';');
        if (semi_colon_pos != std::string::npos)
        {
            // found an option without a colon, so set stream
            // to semi-colon
            std::istringstream::off_type off = 1 +
                (std::streamoff)(tmp_pos) + (std::streamoff)(semi_colon_pos);
            data_stream.seekg(off);
            rule_keyword = rule_keyword.substr(0, semi_colon_pos);
        }

        // now, lets get the next option.
        util::trim(rule_keyword);

        if (rule_keyword == opt_name)
        {
            // Get the value if there is one!
            if (semi_colon_pos == std::string::npos)
                val = util::get_rule_option_args(data_stream);

            break;
        }

        if (semi_colon_pos == std::string::npos)
            std::getline(data_stream, rule_keyword, ';');

        tmp_pos = data_stream.tellg();
    }

    // reset the original state
    if (curr_pos == -1)
        data_stream.setstate(std::ios::eofbit);
    else
        data_stream.clear();

    data_stream.seekg(curr_pos);
    return val;
}

bool file_exists(const std::string& name)
{
    struct stat buffer;
    return (stat (name.c_str(), &buffer) == 0);
}

bool is_regular_file(std::string& path)
{
    struct stat s;

    if (stat(path.c_str(), &s) == 0)
        return (s.st_mode & S_IFREG);

    return false;
}

bool case_compare(std::string arg1, std::string arg2)
{
    std::transform(arg1.begin(), arg1.end(), arg1.begin(), ::tolower);
    std::transform(arg2.begin(), arg2.end(), arg2.begin(), ::tolower);

    if (arg1 == arg2)
        return true;
    return false;
}
} // namespace util
