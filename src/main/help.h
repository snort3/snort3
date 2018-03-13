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
// help.h author Russ Combs <rucombs@cisco.com>

#ifndef HELP_H
#define HELP_H

// utility methods that provide output modes other than the normal packet
// processing.  these are called based on command line arguments.

namespace snort
{
struct SnortConfig;
}

void config_markup(snort::SnortConfig*, const char*);

void help_args(const char* pfx);
[[noreturn]] void help_basic(snort::SnortConfig*, const char*);
[[noreturn]] void help_usage(snort::SnortConfig*, const char*);
[[noreturn]] void help_options(snort::SnortConfig*, const char*);
[[noreturn]] void help_signals(snort::SnortConfig*, const char*);
[[noreturn]] void help_config(snort::SnortConfig* sc, const char*);
[[noreturn]] void help_commands(snort::SnortConfig* sc, const char*);
[[noreturn]] void help_gids(snort::SnortConfig* sc, const char*);
[[noreturn]] void help_buffers(snort::SnortConfig* sc, const char*);
[[noreturn]] void help_builtin(snort::SnortConfig* sc, const char*);
[[noreturn]] void help_module(snort::SnortConfig* sc, const char*);
[[noreturn]] void help_modules(snort::SnortConfig* sc, const char*);
[[noreturn]] void help_plugins(snort::SnortConfig* sc, const char*);
[[noreturn]] void help_version(snort::SnortConfig*);
[[noreturn]] void help_counts(snort::SnortConfig* sc, const char*);

[[noreturn]] void list_modules(snort::SnortConfig* sc, const char*);
[[noreturn]] void list_plugins(snort::SnortConfig* sc, const char*);
[[noreturn]] void list_interfaces(snort::SnortConfig*);
[[noreturn]] void list_daqs(snort::SnortConfig* sc);

[[noreturn]] void dump_defaults(snort::SnortConfig* sc, const char*);
[[noreturn]] void dump_builtin_rules(snort::SnortConfig* sc, const char*);
[[noreturn]] void dump_dynamic_rules(snort::SnortConfig* sc, const char*);
[[noreturn]] void dump_msg_map(snort::SnortConfig* sc, const char*);
[[noreturn]] void dump_rule_hex(snort::SnortConfig* sc, const char*);
[[noreturn]] void dump_rule_text(snort::SnortConfig* sc, const char*);
[[noreturn]] void dump_version(snort::SnortConfig* sc);

#endif

