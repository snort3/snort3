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

#ifndef PROCESS_H
#define PROCESS_H

// process oriented services like signal handling, heap info, etc.

enum PigSignal
{
    PIG_SIG_NONE,
    PIG_SIG_QUIT,
    PIG_SIG_TERM,
    PIG_SIG_INT,
    PIG_SIG_RELOAD_CONFIG,
    PIG_SIG_RELOAD_HOSTS,
    PIG_SIG_DUMP_STATS,
    PIG_SIG_ROTATE_STATS,
    PIG_SIG_MAX
};

PigSignal get_pending_signal();
const char* get_signal_name(PigSignal);

void init_signals();
void term_signals();
void help_signals();

void daemonize();
void set_quick_exit(bool);
void set_main_thread();

void trim_heap();
void log_malloc_info();

#endif

