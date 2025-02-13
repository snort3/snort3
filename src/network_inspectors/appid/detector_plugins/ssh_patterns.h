//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

// ssh_patterns.h author Daniel McGarvey <danmcgar@cisco.com>

#ifndef SSH_PATTERNS_H
#define SSH_PATTERNS_H

/*
 * SshPatternMatchers is a wrapper around an unordered_map
 * which maps strings to AppIds. SSH Client Patterns
 * are registered through a lua API, and these mappings
 * are used by AppId to identify clients.
 * An instance of the class is held by OdpContext.
 */

#include <string>
#include <unordered_map>

#include "application_ids.h"

typedef std::unordered_map<std::string, AppId> SshPatternTable;

class SshPatternMatchers
{
public:
    void add_ssh_pattern(const std::string& pattern, AppId id);
    bool has_pattern(const std::string& pattern) const;
    bool empty() const;
    AppId get_appid(const std::string& pattern) const;
    unsigned get_pattern_count();
private:
    SshPatternTable ssh_patterns;
};

#endif
