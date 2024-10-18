//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// file_connector.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef FILE_CONNECTOR_H
#define FILE_CONNECTOR_H

#include <fstream>

#include "framework/connector.h"

#include "file_connector_config.h"

#define FILE_FORMAT_VERSION (1)

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class __attribute__((__packed__)) FileConnectorMsgHdr
{
public:
    FileConnectorMsgHdr(uint32_t length)
    { version = FILE_FORMAT_VERSION; connector_msg_length = length; }

    uint16_t version;
    uint32_t connector_msg_length;
};

class FileConnectorCommon : public snort::ConnectorCommon
{
public:
    FileConnectorCommon(FileConnectorConfig::FileConnectorConfigSet*);
    ~FileConnectorCommon();
};

class FileConnector : public snort::Connector
{
public:
    FileConnector(const FileConnectorConfig& conf) : Connector(conf), cfg(conf) {}

    bool transmit_message(const snort::ConnectorMsg&) override;
    bool transmit_message(const snort::ConnectorMsg&&) override;

    snort::ConnectorMsg receive_message(bool) override;

    bool flush() override
    { file.flush(); return file.good(); }

    std::fstream file;

private:
    bool internal_transmit_message(const snort::ConnectorMsg&);
    snort::ConnectorMsg receive_message_binary();

    const FileConnectorConfig& cfg;
};

#endif
