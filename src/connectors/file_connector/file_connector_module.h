//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// file_connector_module.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef FILE_CONNECTOR_MODULE_H
#define FILE_CONNECTOR_MODULE_H

#include "framework/module.h"

#include "file_connector_config.h"

#define FILE_CONNECTOR_NAME "file_connector"
#define FILE_CONNECTOR_HELP "implement the file based connector"

class FileConnectorModule : public snort::Module
{
public:
    FileConnectorModule();
    ~FileConnectorModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    FileConnectorConfig::FileConnectorConfigSet* get_and_clear_config();

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    FileConnectorConfig::FileConnectorConfigSet* config_set;
    FileConnectorConfig* config;
};

#endif

