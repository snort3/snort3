//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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

// ssh_patterns.cc author Daniel McGarvey <danmcgar@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssh_patterns.h"

void SshPatternMatchers::add_ssh_pattern(const std::string& pattern, AppId id)
{
    ssh_patterns[pattern] = id;
}

bool SshPatternMatchers::has_pattern(const std::string& pattern) const
{
    return ssh_patterns.find(pattern) != ssh_patterns.end();
}

bool SshPatternMatchers::empty() const
{
    return ssh_patterns.empty();
}

AppId SshPatternMatchers::get_appid(const std::string& pattern) const
{
    return ssh_patterns.at(pattern);
}
