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
// snort2lua.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <iostream>
#include <fstream>

#include "utils/converter.h"
#include "init_state.h"
#include "utils/snort2lua_util.h"
#include "option_parser.h"


/****************************************************
 ************  OPTION INFORMATION   *****************
 ****************************************************/

namespace
{

struct Arg: public option::Arg
{
  static void printError(const char* msg1, const option::Option& opt, const char* msg2)
  {
    fprintf(stderr, "%s", msg1);
      fwrite(opt.name, (std::size_t)opt.namelen, 1, stderr);
    fprintf(stderr, "%s", msg2);
  }

  static option::ArgStatus Unknown(const option::Option& option, bool msg)
  {
    if (msg) printError("Unknown option '", option, "'\n");
    return option::ARG_ILLEGAL;
  }

  static option::ArgStatus Required(const option::Option& option, bool msg)
  {
    if (option.arg != 0)
      return option::ARG_OK;

    if (msg) printError("Option '", option, "' requires an argument\n");
    return option::ARG_ILLEGAL;
  }

  static option::ArgStatus NonEmpty(const option::Option& option, bool msg)
  {
    if (option.arg != 0 && option.arg[0] != 0)
      return option::ARG_OK;

    if (msg) printError("Option '", option, "' requires a non-empty argument\n");
    return option::ARG_ILLEGAL;
  }

  static option::ArgStatus Numeric(const option::Option& option, bool msg)
  {
    char* endptr = 0;
    if (option.arg != 0 && strtol(option.arg, &endptr, 10)){};
    if (endptr != option.arg && *endptr == 0)
      return option::ARG_OK;

    if (msg) printError("Option '", option, "' requires a numeric argument\n");
    return option::ARG_ILLEGAL;
  }
};

static const char* help_str = "    --help, -h\t\tprint usage and exit";
static const char* conf_file_str = "    --conf-file, -c\t\toriginal snort configuration file. Specify as many files as you would like";
static const char* output_file_str  = "    --output-file, -o \t\tdefault = snort.lua.   The new Snort++ configuration file name.";
static const char* rule_file_str  = "    --rules-file, -r \t\tWrite all rules to this file. If not specified, rules will be in default output";
static const char* error_file_str  = "    --error-file, -e \t\tSpecify the reject file. Use with '-a' or '--all' to print errors to this file. Default = snort.rej";
static const char* all_str  = "    --all, -a\t\tOutput all data, including errors and differences. (default only prints the new snort.lua.rej file";
static const char* parse_includes_str  = "    --parse_includes, -p\t\tWhen parsing specified input files, follow and parse any 'include <file>'";
static const char* dont_parse_includes_str  = "    --parse-input-files, -i\t\tOnly parse specified input files. do NOT follow any 'include <file> when parsing.";
static const char* parse_mult_str = "    --mult-rule-files, -m\t\tWhen parsing include file named 'file', write rules to file.rules (parse_includes must be turn on)";
static const char* parse_single_str = "    --single-rule-files, -s\t\tWhen parsing include files, pull all data into specified rule files";
static const char* parse_mult_conf_str = "    --mult-conf-files, -n\t\tWhen parsing include file named 'file', write conf data to file.lua (parse_includes must be turn on)";
static const char* parse_single_conf_str = "    --single-conf-files, -t\t\tWhen parsing include files, pull all data into specified output files";
static const char* differences_str  = "    --output-differences, -d\t\tlua syntax aside, output to specified files the differences between your Snort and Snort++ configuration";
static const char* quiet_str  = "    --output-quiet, -d\t\tdon't print to standard out. only output lua and rule syntax to specified files (no comments, errors, or reject)";

enum OptionType
{
    OPT_ENABLE,
    OPT_DIABLE
};

enum OptionInline
{
    OPT_MULT_FILES,
    OPT_SING_FILE,
};

enum PrintType
{
    PRINT_ALL,
    PRINT_DIFFERENCES,
    PRINT_QUIET,
};

enum OptionIndex {
    HELP,
    CONF_FILE,
    OUTPUT_FILE,
    RULE_FILE,
    ERROR_FILE,
    PARSE_INCLUDES,
    MULT_RULE_FILES,
    MULT_CONF_FILES,
    PRINT_MODE,
    UNKNOWN,
};

const option::Descriptor usage[] =
{
    {HELP, 0, "h", "help", Arg::None, help_str },
    {CONF_FILE, 0, "c", "conf-file", Arg::Required, conf_file_str},
    {OUTPUT_FILE, 0, "o", "output-file", Arg::Required, output_file_str },
    {RULE_FILE, 0, "r", "rules-file", Arg::Required, rule_file_str },
    {ERROR_FILE, 0, "e", "error-file", Arg::Required, error_file_str },
    {PARSE_INCLUDES, OPT_MULT_FILES, "p", "parse-includes", Arg::None, parse_includes_str },
    {PARSE_INCLUDES, OPT_SING_FILE, "i", "parse-input-files", Arg::None, dont_parse_includes_str },
    {MULT_RULE_FILES, OPT_MULT_FILES, "m", "mult-rule-files", Arg::None, parse_mult_str },
    {MULT_RULE_FILES, OPT_SING_FILE, "s", "single-rule-file", Arg::None, parse_single_str },
    {MULT_CONF_FILES, OPT_MULT_FILES, "n", "mult-conf-files", Arg::None, parse_mult_conf_str },
    {MULT_CONF_FILES, OPT_SING_FILE, "t", "mult-conf-files", Arg::None, parse_single_conf_str },
    {PRINT_MODE, PRINT_QUIET, "q", "output-quiet", Arg::None, quiet_str },
    {PRINT_MODE, PRINT_DIFFERENCES, "d", "output-differences", Arg::None, differences_str },
    {PRINT_MODE, PRINT_ALL, "a", "all", Arg::None, all_str },
    {UNKNOWN, 0, "", "", option::Arg::None, ""},
    {0,0,0,0,0,0}
};

} // anonymous


/*********************************************
 **************  MAIN FILES  *****************
 *********************************************/

static bool quiet_mode = false;

static void print_line(std::string s)
{
    if (!quiet_mode)
        std::cout << s << std::endl;
}

static void mult_include_errors(std::string opt_type, std::string file_name)
{
    print_line("Multiple options provided!! Ignoring option " +
            opt_type + ": " + file_name);
}


int main (int argc, char* argv[])
{
    std::string output_file = std::string();
    std::string error_file = std::string();
    std::string rule_file = std::string();
    bool rule_file_specifed = false;
    bool fail = false;;
    Converter cv;
    LuaData ld;

    // increment past the program name
    argc -= (argc > 0) ? 1 : 0;
    argv += (argc > 0) ? 1 : 0;

    // Parse all options
    option::Stats stats(usage, argc, argv);
    option::Option* options = new option::Option[stats.options_max];
    option::Option* buffer = new option::Option[stats.buffer_max];
    option::Parser parse(true, usage, argc, argv, options, buffer);



    if (options[HELP])
    {
        option::printUsage(std::cout, usage);
        return 0;
    }


    // Determines type of printing to output. Since Quiet mode referrs
    // to both output and standard out, parse this option first.
    if (options[PRINT_MODE])
    {
        std::string mode = std::string();

        switch(options[PRINT_MODE].last()->type())
        {
            case PRINT_ALL:
                quiet_mode = false;
                ld.set_default_print();
                mode = "all";
                break;
            case PRINT_QUIET:
                quiet_mode = true;
                ld.set_quiet_print();
                mode = "quiet";
                break;
            case PRINT_DIFFERENCES:
                quiet_mode = false;
                ld.set_difference_print();
                mode = "differences";
                break;
        }

        if (options[PRINT_MODE].count() > 1)
            print_line("Multiple print modes provided. "
                "Running in " + mode + " mode");
    }
    else
    {
        quiet_mode = true;
        ld.set_quiet_print();
    }

    // Get the output file.  Warn the user if they provided multiple
    // files
    if (options[OUTPUT_FILE])
    {
        option::Option* tmp = options[OUTPUT_FILE];
        while (!tmp->isLast())
        {
            mult_include_errors("output-file", tmp->arg);
            tmp = tmp->next();
        }
        output_file = tmp->arg;
        print_line("writing output to " + output_file);
    }
    else
    {
        print_line("No output files provided!  Writing to: snort.lua");
        output_file = "snort.lua";
    }


    // Get the specified rule file.  Warn the user if they provided
    // multiple file name.
    if (options[RULE_FILE])
    {
        option::Option* tmp = options[RULE_FILE];
        while (!tmp->isLast())
        {
            mult_include_errors("rule-file", tmp->arg);
            tmp = tmp->next();
        }
        rule_file = tmp->arg;
        print_line("writing rules to " + rule_file);
    }
    else
    {
        print_line("Rule file not provided!!  Writing rules to " + output_file);
        rule_file = output_file;
    }

    // Get the error/reject file.  Warn the user if they provided multiple
    // files
    if (options[ERROR_FILE])
    {
        option::Option* tmp = options[ERROR_FILE];
        while (!tmp->isLast())
        {
            mult_include_errors("error-file", tmp->arg);
            tmp = tmp->next();
        }
        error_file = tmp->arg;
        print_line("writing errors to " + error_file);
    }
    else
    {
        print_line("Rejects file not provided!!  Writing rejects to snort.lua.rej");
        error_file = "snort.lua.rej";
    }


    // tell the converter to parse all 'include' files
    if (options[PARSE_INCLUDES])
    {
        if (options[PARSE_INCLUDES].last()->type() == OPT_MULT_FILES)
            cv.set_parse_includes(true);
        else
            cv.set_parse_includes(false);
    }

    //  assuming we are parsing includes, should we pull all of the rules into
    //  the specified rule file or keep all rule files seperate
    if (options[MULT_RULE_FILES])
    {
        if (options[MULT_RULE_FILES].last()->type() == OPT_MULT_FILES)
            cv.set_convert_rules_mult_files(true);
        else
            cv.set_convert_rules_mult_files(false);
    }

    //  assuming we are parsing includes, should we pull all of the configuration details
    //  in the specified output file or keep all rule files seperate
    if (options[MULT_CONF_FILES])
    {
        if (options[MULT_CONF_FILES].last()->type() == OPT_MULT_FILES)
            cv.set_convert_conf_mult_files(true);
        else
            cv.set_convert_conf_mult_files(false);
    }

    if (options[UNKNOWN])
    {

    }


    if (!options[CONF_FILE])
    {
        option::printUsage(std::cout, usage);
        std::cout << std::endl << "At least one input file required." << std::endl << std::endl;
        return -1;
    }





    cv.initialize(&init_state_ctor, &ld);

    // MAIN LOOP!!   walk through every input file and begin converting!
    option::Option* opt = options[CONF_FILE];
    do {
        if (cv.convert_file(std::string(opt->arg)) < 0)
        {
            print_line("Failed Conversion of file " + std::string(opt->arg));
            fail = true;
        }
    } while ((opt = opt->next()));



    // if no rule file is specified (or the same output and rule file specified),
    // rules will be printed in the 'default_rules' variable. Set that up
    // now.  Otherwise, set up the include file.
    if (ld.contains_rules())
    {
        if (rule_file.empty() || !rule_file.compare(output_file))
        {
            std::string s = std::string("$default_rules");
            rule_file_specifed = false;

            ld.open_top_level_table("ips");
            ld.add_option_to_table("rules", s);
            ld.close_table();
        }
        else
        {
            rule_file_specifed = true;

            ld.open_top_level_table("ips");
            ld.add_option_to_table("include", rule_file);
            ld.close_table();
        }
    }

    // Snort++ requires a binder table to be instantiated,
    // although not necessarily filled.  So, just add this table.
    // If its already added, these lines won't have any effect
    ld.open_top_level_table("binder");
    ld.close_table();

    // finally, lets print the converter to file

    std::ofstream out;
    out.open(output_file,  std::ifstream::out);
    out << "require(\"snort_config\")  -- for loading\n\n";

    if (!rule_file_specifed)
    {
        ld.print_rules(out, rule_file_specifed);
        ld.print_conf_options(out);

        out << std::endl;

        if (ld.failed_conversions() && !ld.is_quiet_mode())
        {
            std::ofstream rejects;  // in this case, rejects are regular configuration options
            rejects.open(error_file, std::ifstream::out);
            ld.print_rejects(rejects);
            rejects << std::endl;
            rejects.close();
        }
    }
    else
    {
        std::ofstream rules;
        rules.open(rule_file, std::ifstream::out);

        ld.print_rules(rules, rule_file_specifed);
        ld.print_conf_options(out);

        // flush all data
        out << std::endl;
        rules << std::endl;
        rules.close();

        if (ld.failed_conversions() && !ld.is_quiet_mode())
        {
            std::ofstream rejects;
            rejects.open(error_file, std::ifstream::out);
            ld.print_rejects(rejects);
            rejects << std::endl;
            rejects.close();
        }
    }


    out.close();
    delete[] options;
    delete[] buffer;

    if (fail || ld.failed_conversions())
        return -2;
    return 0;
}
