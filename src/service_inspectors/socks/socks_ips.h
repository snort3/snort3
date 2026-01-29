//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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
// socks_ips.h author Raza Shafiq <rshafiq@cisco.com>

#ifndef SOCKS_IPS_H
#define SOCKS_IPS_H

namespace snort
{
    struct SnortConfig;
}

void ips_socks_version_init();
void ips_socks_command_init();
void ips_socks_address_type_init();
void ips_socks_remote_address_init();
void ips_socks_remote_port_init();

#endif
