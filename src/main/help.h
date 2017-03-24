//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

struct SnortConfig;

void config_markup(SnortConfig*, const char*);

void help_args(const char* pfx);
void help_basic(SnortConfig*, const char*);
void help_usage(SnortConfig*, const char*);
void help_options(SnortConfig*, const char*);
void help_signals(SnortConfig*, const char*);
void help_config(SnortConfig* sc, const char*);
void help_commands(SnortConfig* sc, const char*);
void help_gids(SnortConfig* sc, const char*);
void help_buffers(SnortConfig* sc, const char*);
void help_builtin(SnortConfig* sc, const char*);
void help_module(SnortConfig* sc, const char*);
void help_modules(SnortConfig* sc, const char*);
void help_plugins(SnortConfig* sc, const char*);
void help_version(SnortConfig*);
void help_counts(SnortConfig* sc, const char*);

void list_modules(SnortConfig* sc, const char*);
void list_plugins(SnortConfig* sc, const char*);
void list_interfaces(SnortConfig*);
void list_daqs(SnortConfig* sc);

void dump_defaults(SnortConfig* sc, const char*);
void dump_builtin_rules(SnortConfig* sc, const char*);
void dump_dynamic_rules(SnortConfig* sc, const char*);
void dump_rule_hex(SnortConfig* sc, const char*);
void dump_rule_text(SnortConfig* sc, const char*);
void dump_version(SnortConfig* sc);

#endif

