//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// ips_opcua_mock.h author Daniil Kolomiiets <dkolomii@cisco.com>

#ifndef IPS_OPCUA_MOCK_H
#define IPS_OPCUA_MOCK_H

#include "opcua_mock.h"
#include "src/framework/ips_option.h"
#include "src/framework/cursor.h"

static OpcuaFlowData* ofd = nullptr;

namespace snort
{

IpsOption::IpsOption(const char*, option_type_t) { }
uint32_t IpsOption::hash() const { return 0; }
uint16_t IpsOption::get_pdu_section(bool) const { return 0; }
bool IpsOption::operator==(const IpsOption&) const { return true; }

FlowDataStore::~FlowDataStore() { }
FlowData* FlowDataStore::get(unsigned) const { return ofd; }
void FlowDataStore::set(FlowData*) { }

Flow::~Flow() { }

Module::Module(char const*, char const*, Parameter const*, bool) {}
Module::Module(char const*, char const*) {}
void Module::sum_stats(bool) {}
void Module::show_interval_stats(std::vector<unsigned>&, FILE*) {}
void Module::show_stats() {}
void Module::init_stats(bool) {}
void Module::reset_stats() {}
void Module::main_accumulate_stats() {}
PegCount Module::get_global_count(char const*) const { return 0; }

bool Value::strtoul(unsigned long& n) const { n = 123; return true; }
}


#endif // IPS_OPCUA_MOCK_H