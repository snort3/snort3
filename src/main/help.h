//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
class Module;
struct SnortConfig;
}

void config_markup(snort::SnortConfig*, const char*);

[[noreturn]] void help_basic(snort::SnortConfig*, const char*);
[[noreturn]] void help_buffers(const snort::SnortConfig*, const char*);
[[noreturn]] void help_builtin(const snort::SnortConfig*, const char*);
[[noreturn]] void help_commands(const snort::SnortConfig*, const char*);
[[noreturn]] void help_config(const snort::SnortConfig*, const char*);
[[noreturn]] void help_counts(const snort::SnortConfig*, const char*);
[[noreturn]] void help_gids(const snort::SnortConfig*, const char*);
[[noreturn]] void help_limits(snort::SnortConfig*, const char*);
[[noreturn]] void help_module(const snort::SnortConfig*, const char*);
[[noreturn]] void help_modules(const snort::SnortConfig*, const char*);
[[noreturn]] void help_modules_json(const snort::SnortConfig*, const char*);
[[noreturn]] void help_options(snort::SnortConfig*, const char*, const snort::Module*);
[[noreturn]] void help_plugins(const snort::SnortConfig*, const char*);
[[noreturn]] void help_signals(snort::SnortConfig*, const char*);
[[noreturn]] void help_usage(snort::SnortConfig*, const char*);
[[noreturn]] void help_version(snort::SnortConfig*);

[[noreturn]] void list_daqs(const snort::SnortConfig*);
[[noreturn]] void list_modules(const snort::SnortConfig*, const char*);
[[noreturn]] void list_plugins(const snort::SnortConfig*, const char*);

[[noreturn]] void dump_builtin_rules(const snort::SnortConfig*, const char*, const char*);
[[noreturn]] void dump_defaults(const snort::SnortConfig*, const char*);
[[noreturn]] void dump_dynamic_rules(const snort::SnortConfig*, const char*);
[[noreturn]] void dump_modules(const snort::SnortConfig*);
[[noreturn]] void dump_rule_hex(snort::SnortConfig*, const char*);
[[noreturn]] void dump_rule_text(snort::SnortConfig*, const char*);
[[noreturn]] void dump_version(snort::SnortConfig*);

#endif
