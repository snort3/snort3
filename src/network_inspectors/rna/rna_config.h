//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// rna_config.h author Masud Hasan <mashasan@cisco.com>

#ifndef RNA_CONFIG_H
#define RNA_CONFIG_H

struct RnaModuleConfig
{
    std::string rna_conf_path;
    std::string rna_util_lib_path;
    std::string fingerprint_dir;
    std::string custom_fingerprint_dir;
    bool enable_logger;
    bool log_when_idle;
};

// Give default values so that RNA can work even if rna_conf_path is not provided
struct RnaConfig
{
    uint32_t update_timeout = 3600;
    uint16_t max_host_client_apps = 16;
    uint16_t max_payloads = 100;
    uint16_t max_host_services = 100;
    uint16_t max_host_service_info = 16;
    bool enable_banner_grab = 0;
    bool log_when_idle = 0;
};

#endif
