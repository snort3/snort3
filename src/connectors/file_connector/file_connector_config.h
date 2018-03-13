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

// file_connector_config.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef FILE_CONNECTOR_CONFIG_H
#define FILE_CONNECTOR_CONFIG_H

#include <string>
#include <vector>

#include "framework/connector.h"

class FileConnectorConfig : public snort::ConnectorConfig
{
public:
    FileConnectorConfig()
    { direction = snort::Connector::CONN_UNDEFINED; text_format = false; }

    bool text_format;
    std::string name;

    typedef std::vector<FileConnectorConfig*> FileConnectorConfigSet;
};

#endif

