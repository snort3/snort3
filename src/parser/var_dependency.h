//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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

// var_dependency.h author Yurii Chalov <ychalov@cisco.com>

#ifndef VAR_DEPENDENCY_H
#define VAR_DEPENDENCY_H

void resolve_nets();
void resolve_ports();

bool is_resolving_nets();
bool is_resolving_ports();

void push_to_weak_nets(const char* var_name, const char* val);
void push_to_weak_ports(const char* var_name, const char* val);

#endif
