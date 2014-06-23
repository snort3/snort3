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
// snort2lua.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <iostream>
#include <fstream>

#include "converter.h"
#include "init_state.h"
#include "snort2lua_util.h"
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
    fwrite(opt.name, opt.namelen, 1, stderr);
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

enum OptionType {
    OPT_ENABLE,
    OPT_DIABLE
};

enum OptionIndex {
    INPUT_FILE,
    OUTPUT_FILE,
    HELP,
    READ_INCLUDE_FILES,
    UNKOWN,
};
const option::Descriptor usage[] =
{
    {HELP, 0, "", "help", Arg::None, "  --help\t\tprint usage and exit"},
    {INPUT_FILE, 0, "c", "input", Arg::Required, "  -i --input-file, \t\tsnort configuration file. Specify as many files as you would like"},
    {OUTPUT_FILE, 0, "o", "output", Arg::Required, "  --output-file, -o \t\tThe new Snort++ configuration file name"},
    {READ_INCLUDE_FILES, OPT_ENABLE, "", "enable-reading-includes", Arg::None, "  enable-reading-includes \t\t Every time the 'include' keywords appears, open and parse that file"},
    {READ_INCLUDE_FILES, OPT_DIABLE, "", "disable-reading-includes", Arg::None, "  disable-reading-includes  \t\tEvery time the 'include' keywords appears, open and parse that file"},
    {0,0,0,0,0,0}
};

} // anonymous


/*********************************************
 **************  MAIN FILES  *****************
 *********************************************/

void convert(Converter *cv, std::string input_file)
{
    std::ifstream in;
    std::string orig_text;

    cv->reset_state();
    in.open(input_file,  std::ifstream::in);


    if (in.fail())
    {
        cv->add_comment_to_file("Unable to open file " + input_file);
        return;
    }

    while(!in.eof())
    {
        std::string tmp;
        std::getline(in, tmp);
        util::ltrim(tmp);
        orig_text += ' ' + tmp;
        util::trim(orig_text);

        if (orig_text.empty())
        {
            cv->add_comment_to_file("");
        }
        else if (orig_text.front() == '#')
        {
            orig_text.erase(orig_text.begin());
            util::ltrim(orig_text);
            cv->add_comment_to_file(orig_text);
            orig_text.clear();
        }
        else if ( orig_text.back() == '\\')
        {
            orig_text.pop_back();
            util::rtrim(orig_text);
        }
        else
        {
            std::stringstream data_stream(orig_text);
            while(data_stream.tellg() != -1)
            {
                if (!cv->convert_line(data_stream))
                {
                    cv->log_error("Failed to entirely convert: " + orig_text);
                    break;
                }
            }

            orig_text.clear();
            cv->reset_state();
        }
    }

}


int main (int argc, char* argv[])
{
    std::ifstream in;
    std::ofstream out;
    std::string input_name, output_name;
    Converter cv;

    // increment past the program name
    argc -= (argc > 0) ? 1 : 0;
    argv += (argc > 0) ? 1 : 0;

    option::Stats stats(usage, argc, argv);
    option::Option* options = new option::Option[stats.options_max];
    option::Option* buffer = new option::Option[stats.buffer_max];
    option::Parser parse(true, usage, argc, argv, options, buffer);

    if (options[HELP])
    {
        option::printUsage(std::cout, usage);
        return 0;
    }

    if (options[INPUT_FILE].count() == 0)
    {
        option::printUsage(std::cout, usage);
        std::cout << std::endl << "At least one input file required." << std::endl << std::endl;
        return -1;
    }

    if (options[OUTPUT_FILE].count() != 1)
    {
        option::printUsage(std::cout, usage);

        if(options[OUTPUT_FILE].count() == 0)
            std::cout << std::endl << "At least one input file required." << std::endl << std::endl;
        else
            std::cout << std::endl << "Only one output file is allowed!" << std::endl << std::endl;

        return -1;
    }

    if (options[READ_INCLUDE_FILES])
    {
        switch(options[READ_INCLUDE_FILES].last()->type())
        {
            case OPT_ENABLE:
                std::cout << "parsing include files" << std::endl;
                break;
            case OPT_DIABLE:
                std::cout << "absolutely avoiding those includes" << std::endl;
                break;
        }
    }

    // read and convert every include files
    option::Option* opt = options[INPUT_FILE];
    do {
        convert(&cv, std::string(opt->arg));
    } while ((opt = opt->next()));



    // finally, lets print the converter to file
    output_name = options[OUTPUT_FILE].arg;
    out.open(output_name,  std::ifstream::out);
    out << "require(\"snort_config\")  -- for loading" << std::endl << std::endl;
    out << cv;

    in.close();
    out.close();
    delete[] options;
    delete[] buffer;
    return 0;
}
