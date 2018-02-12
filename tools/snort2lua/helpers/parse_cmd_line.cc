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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "parse_cmd_line.h"

#include <cstring>
#include <iomanip>

#include "converter.h"
#include "s2l_markup.h"
#include "s2l_util.h"

namespace parser
{
typedef void (* ParseConfigFunc)(const char*, const char* val);
struct ConfigFunc
{
    const char* name;
    ParseConfigFunc parse_func;
    std::string type;
    const char* help;
};

static const std::string out_default = "snort.lua";
static const std::string error_default = "snort.rej";

static std::string conf_file = std::string();
static std::string conf_dir = std::string();
static std::string error_file = std::string();
static std::string out_file = std::string();
static std::string rule_file = std::string();
bool found_error_file = false;
bool found_out_file = false;
bool found_rule_file = false;

const std::string get_conf()
{ return conf_file; }

const std::string get_conf_dir()
{ return conf_dir; }

const std::string get_error_file()
{ return error_file.empty() ? error_default : error_file; }

const std::string get_out_file()
{ return out_file.empty() ? out_default : out_file; }

const std::string get_rule_file()
{ return rule_file.empty() ? get_out_file() : rule_file; }

static void help_args(const char* pfx, const char* /*val*/);

//-------------------------------------------------------------------------
// arg foo
//-------------------------------------------------------------------------

class ArgList
{
public:
    ArgList(int c, char* v[])
    { argc = c; argv = v; reset(); }

    void reset()
    { idx = 0; arg = nullptr; }

    bool get_arg(const char*& key, const char*& val);
    void dump();

private:
    char** argv;
    int argc, idx;
    const char* arg;
    std::string buf;
};

void ArgList::dump()
{
    for ( int i = 0; i < argc; ++i )
        printf("argv[%d]='%s'\n", i, argv[i]);
}

// FIXIT-L this chokes on -n -4 because it thinks
// -4 is another arg instead of an option to -n
bool ArgList::get_arg(const char*& key, const char*& val)
{
    while ( ++idx < argc )
    {
        char* s = argv[idx];

        if ( arg )
        {
            key = arg;
            if ( s[0] != '-' )
                val = s;
            else
            {
                val = "";
                --idx;
            }
            arg = nullptr;
            return true;
        }
        if ( s[0] != '-' )
        {
            key = "";
            val = s;
            return true;
        }
        if ( s[1] != '-' )
        {
            s += 1;
            if ( strlen(s) > 1 )
            {
                buf.assign(s, 1);
                key = buf.c_str();
                val = s + 1;
                return true;
            }
            else if ( strlen(s) > 0 )
                arg = s;
            else
                arg = "-";
        }
        else
        {
            s += 2;
            char* eq = strchr(s, '=');

            if ( eq )
            {
                buf.assign(s, eq-s);
                key=buf.c_str();
                val = eq + 1;
                return true;
            }
            else
                arg = s;
        }
    }
    if ( arg )
    {
        key = arg;
        val = "";
        arg = nullptr;
        return true;
    }
    return false;
}

[[noreturn]] static void help_usage()
{
    std::cout << "usage:\n";
    std::cout << "    -?: list options\n";
    std::cout << "    -V: output version\n";
    std::cout << "    --help: help summary\n";
    exit(0);
}

/*
 * MOST OF THIS FUNCTION IS TAKEN FROM SNORT!!
 * -- therefore, when it fails due to its simplicity
 * on some operating system, I get to say this worked
 * for Snort and a valid configuration is required!!
 */
static void parse_config_file(const char* key, const char* val)
{
    if (!conf_file.empty())
    {
        std::cout << "ERROR: " << key << " " << val << "\n\tOnly one config file allowed!\n";
        exit(-1);
    }
    else
    {
        conf_file = std::string(val);
        std::size_t path_sep = conf_file.find_last_of('/');

        /* is there a directory separator in the filename */
        if (path_sep != std::string::npos)
        {
            path_sep++;  /* include path separator */
            conf_dir = conf_file.substr(0, path_sep);
        }
        else
        {
            conf_dir = std::string("./");
        }
    }
}

static void parse_error_file(const char* key, const char* val)
{
    if (found_error_file)
    {
        std::cout << "ERROR: " << key << " " << val << "\n\tOnly one error file allowed!\n";
        exit(-1);
    }
    else
    {
        error_file = std::string(val);
        found_error_file = true;
    }
}

static void parse_output_file(const char* key, const char* val)
{
    if (found_out_file)
    {
        std::cout << "ERROR: " << key << " " << val << "\n\tOnly one output file allowed!\n";
        exit(-1);
    }
    else
    {
        found_out_file = true;
        out_file = std::string(val);
    }
}

static void parse_rule_file(const char* key, const char* val)
{
    if (found_rule_file)
    {
        std::cout << "ERROR: " << key << " " << val << "\n\tOnly one output file allowed!\n";
        exit(-1);
    }
    else
    {
        found_rule_file = true;
        rule_file = std::string(val);
    }
}

static void add_remark(const char* /*key*/, const char* val)
{ RuleApi::set_remark(val); }

static void bind_wizard(const char* /*key*/, const char* /*val*/)
{ Converter::set_bind_wizard(true); }

static void print_all(const char* /*key*/, const char* /*val*/)
{ DataApi::set_default_print(); }

static void print_quiet(const char* /*key*/, const char* /*val*/)
{ DataApi::set_quiet_print(); }

static void print_differences(const char* /*key*/, const char* /*val*/)
{ DataApi::set_difference_print(); }

static void sing_rule_files(const char* /*key*/, const char* /*val*/)
{ Converter::create_mult_rule_files(false); }

static void sing_conf_files(const char* /*key*/, const char* /*val*/)
{ Converter::create_mult_conf_files(false); }

static void dont_parse_includes(const char* /*key*/, const char* /*val*/)
{ Converter::set_parse_includes(false); }

static void enable_markup(const char* /*key*/, const char* /*val*/)
{ Markup::enable(true); }

static void set_ips_pattern(const char* /*key*/, const char* val)
{ Converter::set_ips_pattern(val); }

static void print_version(const char* /*key*/, const char* /*val*/)
{
    std::cout << "Snort2Lua\t0.2.0";
}

#ifdef REG_TEST
[[noreturn]] static void print_binder_order(const char* /*key*/, const char* /*val*/)
{
    print_binder_priorities();
    exit(0);
}
#endif

[[noreturn]] static void help(const char* key, const char* val)
{
    std::cout << Markup::head(3) << "Usage: snort2lua [OPTIONS]... -c <snort_conf> ...\n";
    std::cout << "\n";
    std::cout << "Converts the Snort configuration file specified by the -c or --conf-file\n";
    std::cout << "options into a Snort++ configuration file\n";
    std::cout << "\n";
    std::cout << "\n";
    std::cout << "\n";
    std::cout << Markup::head(4) << "Options:\n\n";
    help_args(key, val);
    std::cout << "\n";
    std::cout << "\n";
    std::cout << "\n";
    std::cout << Markup::head(4) << "Required option:\n\n";
    std::cout << Markup::item() <<
            "\tA Snort configuration file to convert. Set with either '-c' or '--conf-file'\n";
    std::cout << "\n";
    std::cout << "\n";
    std::cout << Markup::head(4) << "Default values:\n";
    std::cout << Markup::item() << "\t<out_file>   =  " << out_default << "\n";
    std::cout << Markup::item() << "\t<rule_file>  =  <out_file> = " << out_default <<
        ".  Rules are written to the 'local_rules' variable in the <out_file>\n";
    std::cout << Markup::item() << "\t<error_file> =  " << error_default <<
        ".  This file will not be created in quiet mode.\n";
    std::cout << "\n";
    exit(0);
}

[[noreturn]] static void print_args(const char* key, const char* val)
{
    help_args(key, val);
    exit(0);
}

static ConfigFunc basic_opts[] =
{
    { "?", print_args, "",
      "show usage" },

    { "h", help, "",
      "this overview of snort2lua" },

    { "a", print_all, "",
      "default option.  print all data" },

    { "c", parse_config_file, "<snort_conf>",
      "The Snort <snort_conf> file to convert" },

    { "d", print_differences, "",
      "print the differences, and only the differences, between the Snort "
      "and Snort++ configurations to the <out_file>" },

    { "e", parse_error_file, "<error_file>",
      "output all errors to <error_file>" },

    { "i", dont_parse_includes, "",
      "if <snort_conf> file contains any <include_file> or <policy_file> "
      "(i.e. 'include path/to/conf/other_conf'), do NOT parse those files" },

    { "m", add_remark, "",
      "add a remark to the end of every converted rule" },

    { "o", parse_output_file, "<out_file>",
      "output the new Snort++ lua configuration to <out_file>" },

    { "q", print_quiet, "",
      "quiet mode. Only output valid configuration information to the <out_file>" },

    { "r", parse_rule_file, "<rule_file>",
      "output any converted rule to <rule_file>" },

    { "s", sing_rule_files, "",
      "when parsing <include_file>, write <include_file>'s rules to "
      "<rule_file>. Meaningless if '-i' provided" },

    { "t", sing_conf_files, "",
      "when parsing <include_file>, write <include_file>'s information, "
      "excluding rules, to <out_file>. Meaningless if '-i' provided" },

    { "V", print_version, "",
      "Print the current Snort2Lua version" },

    { "bind-wizard", bind_wizard, "",
      "Add default wizard to bindings" },

    { "conf-file", parse_config_file, "",
      "Same as '-c'. A Snort <snort_conf> file which will be converted" },

    { "dont-parse-includes", dont_parse_includes, "",
      "Same as '-p'. if <snort_conf> file contains any <include_file> or <policy_file> "
      "(i.e. 'include path/to/conf/other_conf'), do NOT parse those files" },

    { "error-file", parse_error_file, "<error_file>",
      "Same as '-e'. output all errors to <error_file>" },

    { "help", help, "",
      "Same as '-h'. this overview of snort2lua" },

    { "ips-policy-pattern", set_ips_pattern, "",
      "Convert config bindings matching this path to ips policy bindings" },

    { "markup", enable_markup, "",
      "print help in asciidoc compatible format" },

    { "output-file", parse_output_file, "<out_file>",
      "Same as '-o'. output the new Snort++ lua configuration to <out_file>" },

    { "print-all", print_all, "",
      "Same as '-a'. default option.  print all data" },

#ifdef REG_TEST
    { "print-binding-order", print_binder_order, "",
      "Print sorting priority used when generating binder table" },
#endif

    { "print-differences", print_differences, "",
      "Same as '-d'. output the differences, and only the differences, "
      "between the Snort and Snort++ configurations to the <out_file>" },

    { "quiet", print_quiet, "",
      "Same as '-q'. quiet mode. Only output valid configuration information to the <out_file>" },

    { "remark", add_remark, "",
      "same as '-m'.  add a remark to the end of every converted rule" },

    { "rule-file", parse_rule_file, "<rule_file>",
      "Same as '-r'. output any converted rule to <rule_file>" },

    { "single-conf-file", sing_conf_files, "",
      "Same as '-t'. when parsing <include_file>, write <include_file>'s information, excluding rules, to <out_file>" },

    { "single-rule-file", sing_rule_files, "",
      "Same as '-s'. when parsing <include_file>, write <include_file>'s rules to <rule_file>." },

    { "version", print_version, "",
      "Same as '-V'. Print the current Snort2Lua version" },

    { nullptr, nullptr, "", nullptr, }
};

bool parse_cmd_line(int argc, char* argv[])
{
    ArgList al(argc, argv);
    const char* key, * val;
    bool found_opt = false;

    while ( al.get_arg(key, val) )
    {
        ConfigFunc* p = basic_opts;

        while ( p->name && strcmp(p->name, key) )
            ++p;

        if ( !p->name )
        {
            return false;
        }
        else
        {
            p->parse_func(key, val);
        }

        found_opt = true;
    }

    if (!found_opt)
        help_usage();

    return true;
}

static void help_args(const char* /*pfx*/, const char* /*val*/)
{
    ConfigFunc* p = basic_opts;
    const int name_field_len = 20;
    const int data_field_len = 80 - name_field_len;

    while ( p->name )
    {
        if ( p->help ) //&& (!n || !strncasecmp(p->name, pfx, n)) )
        {
            bool two_dash = strlen(p->name) > 1;
            std::string name = two_dash ? "--" : "-";
            name += p->name;

            if (!p->type.empty())
            {
                name += two_dash ? "=" : " ";
                name += p->type;
            }

            std::cout << Markup::item();
            std::cout << std::left << std::setw(name_field_len) << Markup::emphasis(name);

            if (name.size() > name_field_len)
                std::cout << "\n" << std::left << std::setw(name_field_len) << " ";

            std::string help = p->help;
            bool first_line = true;

            while (!help.empty())
            {
                std::size_t len = util::get_substr_length(help, data_field_len);

                if (first_line)
                    first_line = false;
                else
                    std::cout << "\n" << std::setw(name_field_len) << " ";

                std::cout << std::left << Markup::escape(help.substr(0, len));

                if (len < help.size())
                    help = help.substr(len + 1);
                else
                    break;
            }

            std::cout << Markup::add_newline() << std::endl;
        }
        ++p;
    }
}
} // namespace parser

