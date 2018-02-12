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

#ifndef HELPERS_PARSE_CMD_LINE_H
#define HELPERS_PARSE_CMD_LINE_H

#include <string>

namespace parser
{
/*
 * This file is directly copied (and then edited)
 * from Snort++'s cmd_line.h
 */

bool parse_cmd_line(int argc, char* argv[]);

const std::string get_conf();
const std::string get_conf_dir();
const std::string get_error_file();
const std::string get_out_file();
const std::string get_rule_file();
} // namespace parser

#endif

