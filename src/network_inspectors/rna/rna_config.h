//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/data_bus.h"

namespace snort
{
class TcpFpProcessor;
class UaFpProcessor;
class UdpFpProcessor;
class SmbFpProcessor;
}

struct RnaModuleConfig
{
    std::string rna_conf_path;
    bool enable_logger;
    bool log_when_idle;
    snort::TcpFpProcessor* tcp_processor = nullptr;
    snort::UaFpProcessor* ua_processor = nullptr;
    snort::UdpFpProcessor* udp_processor = nullptr;
    snort::SmbFpProcessor* smb_processor = nullptr;
};

// Give default values so that RNA can work even if rna_conf_path is not provided
struct RnaConfig
{
    uint32_t update_timeout = 3600;
    uint16_t max_host_client_apps = 16;
    uint16_t max_payloads = 100;
    uint16_t max_host_services = 100;
    uint16_t max_host_service_info = 16;
    bool enable_banner_grab = false;
    bool log_when_idle = false;

    static unsigned pub_id;
};

#endif
