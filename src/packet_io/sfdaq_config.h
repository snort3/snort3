//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// sfdaq_config.h author Michael Altizer <mialtize@cisco.com>

#ifndef SFDAQ_CONFIG_H
#define SFDAQ_CONFIG_H

#include <string>
#include <unordered_map>
#include <vector>

/* Per-Instance override configuration */
struct SFDAQInstanceConfig
{
    SFDAQInstanceConfig() = default;
    SFDAQInstanceConfig(const SFDAQInstanceConfig&);

    SFDAQInstanceConfig& operator=(const SFDAQInstanceConfig&) = delete;

    void set_input_spec(const char*);
    void set_variable(const char* varkvp);

    std::string input_spec;
    std::vector<std::pair<std::string, std::string>> variables;
};

/* General/base configuration */
struct SFDAQConfig
{
    SFDAQConfig();
    ~SFDAQConfig();

    void add_module_dir(const char*);
    void set_input_spec(const char*, int instance_id = -1);
    void set_module_name(const char*);
    void set_mru_size(int);
    void set_variable(const char* varkvp, int instance_id = -1);

    void overlay(const SFDAQConfig*);

    /* General configuration */
    std::vector<std::string> module_dirs;
    std::string module_name;
    /* Module configuration */
    std::string input_spec;
    std::vector<std::pair<std::string, std::string>> variables;
    int mru_size;
    unsigned int timeout;
    std::unordered_map<unsigned, SFDAQInstanceConfig*> instances;
};

#endif
