//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <cstdint>
#include <string>
#include <vector>

using DaqVar = std::pair<std::string, std::string>;
using DaqVarList = std::vector<DaqVar>;

/* Module configuration */
struct SFDAQModuleConfig
{
    enum SFDAQMode
    {
        SFDAQ_MODE_UNSET,
        SFDAQ_MODE_PASSIVE,
        SFDAQ_MODE_INLINE,
        SFDAQ_MODE_READ_FILE,
    };

    SFDAQModuleConfig() = default;
    SFDAQModuleConfig(const SFDAQModuleConfig&);
    void set_variable(const char* varkvp);

    std::string name;
    SFDAQMode mode = SFDAQ_MODE_UNSET;
    DaqVarList variables;
};

/* General/base configuration */
struct SFDAQConfig
{
    SFDAQConfig();
    ~SFDAQConfig();

    void add_input(const char*);
    SFDAQModuleConfig* add_module_config(const char* module_name);
    void add_module_dir(const char*);
    void set_batch_size(uint32_t);
    void set_mru_size(int);

    uint32_t get_batch_size() const { return (batch_size == BATCH_SIZE_UNSET) ? BATCH_SIZE_DEFAULT : batch_size; }
    uint32_t get_mru_size() const { return (mru_size == SNAPLEN_UNSET) ? SNAPLEN_DEFAULT : mru_size; }

    void overlay(const SFDAQConfig*);

    /* General configuration */
    std::vector<std::string> module_dirs;
    /* Instance configuration */
    std::vector<std::string> inputs;
    uint32_t batch_size;
    int mru_size;
    unsigned int timeout;
    std::vector<SFDAQModuleConfig*> module_configs;

    /* Constants */
    static constexpr uint32_t BATCH_SIZE_UNSET = 0;
    static constexpr int SNAPLEN_UNSET = -1;
    static constexpr uint32_t BATCH_SIZE_DEFAULT = 64;
    static constexpr int SNAPLEN_DEFAULT = 1518;
    static constexpr unsigned TIMEOUT_DEFAULT = 1000;
};

#endif
