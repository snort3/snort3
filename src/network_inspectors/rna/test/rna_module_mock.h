//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

// rna_module_mock.h author Masud Hasan <mashasan@cisco.com>

#ifndef RNA_MODULE_MOCK_H
#define RNA_MODULE_MOCK_H

bool Swapper::reload_in_progress = false;
THREAD_LOCAL RnaStats rna_stats;
THREAD_LOCAL ProfileStats rna_perf_stats;
static std::string message;
static Request mock_request;

void Request::respond(const char* msg, bool, bool)
{
    message = msg;
}
Request& get_current_request()
{ return mock_request; }

namespace snort
{
Inspector* InspectorManager::get_inspector(const char*, bool, const SnortConfig*)
{ return nullptr; }
Module::Module(const char*, const char*, const Parameter*, bool) {}
void Module::sum_stats(bool) {}
void Module::show_stats() {}
void Module::reset_stats() {}
PegCount Module::get_global_count(char const*) const
{ return 0; }
void Module::show_interval_stats(std::vector<unsigned int, std::allocator<unsigned int> >&, FILE*)
{}
void LogMessage(const char*,...) {}
void WarningMessage(const char*,...) {}
SnortConfig::SnortConfig(SnortConfig const*) {}
SnortConfig::~SnortConfig() {}
} // end of namespace snort

#endif
