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

// file_connector.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_connector.h"

#include "profiler/profiler_defs.h"
#include "side_channel/side_channel.h"

#include "file_connector_module.h"

using namespace snort;

/* Globals ****************************************************************/

THREAD_LOCAL SimpleStats file_connector_stats;
THREAD_LOCAL ProfileStats file_connector_perfstats;

bool FileConnector::internal_transmit_message(const ConnectorMsg& msg)
{
    if ( !msg.get_data() or msg.get_length() == 0 )
        return false;

    if ( cfg.text_format )
    {
        file.write((const char*)msg.get_data(), msg.get_length());
        file << "\n";
    }
    else
    {
        FileConnectorMsgHdr fc_hdr(msg.get_length());

        file.write((const char*)&fc_hdr, sizeof(fc_hdr) );
        file.write((const char*)msg.get_data(), msg.get_length());
    }

    return file.good();
}

bool FileConnector::transmit_message(const ConnectorMsg& msg, const ID&)
{ return internal_transmit_message(msg); }

bool FileConnector::transmit_message(const ConnectorMsg&& msg, const ID&)
{ return internal_transmit_message(msg); }

ConnectorMsg FileConnector::receive_message_binary()
{
    uint8_t* fc_hdr_buf = new uint8_t[sizeof(FileConnectorMsgHdr)];

    FileConnectorMsgHdr* fc_hdr = (FileConnectorMsgHdr*)fc_hdr_buf;
    file.read((char*)fc_hdr_buf, sizeof(FileConnectorMsgHdr));

    if ( (unsigned)file.gcount() < sizeof(FileConnectorMsgHdr) or
        fc_hdr->connector_msg_length == 0 or fc_hdr->version != FILE_FORMAT_VERSION )
    {
        delete[] fc_hdr_buf;
        return ConnectorMsg();
    }

    uint8_t* data = new uint8_t[fc_hdr->connector_msg_length];
    file.read((char*)data, fc_hdr->connector_msg_length);

    if ( (unsigned)file.gcount() < fc_hdr->connector_msg_length )
    {
        delete[] fc_hdr_buf;
        delete[] data;
        return ConnectorMsg();
    }

    ConnectorMsg msg(data, fc_hdr->connector_msg_length, true);
    delete[] fc_hdr_buf;

    return msg;
}

// Reading messages from files can never block.  Either a message exists
//  or it does not.
ConnectorMsg FileConnector::receive_message(bool)
{
    if ( !file.is_open() )
        return ConnectorMsg();

    if ( cfg.text_format )
    {
        std::string line;
        std::getline(file, line, file.widen('\n'));

        if ( line.empty() )
            return ConnectorMsg();

        uint8_t* data = new uint8_t[line.size()];
        memcpy(data, line.c_str(), line.size());

        return ConnectorMsg(data, line.size(), true);
    }

    return receive_message_binary();
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FileConnectorModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Connector* file_connector_tinit_transmit(std::string& filename, const FileConnectorConfig& cfg)
{
    FileConnector* file_conn = new FileConnector(cfg);
    std::string pathname;

    filename += "_transmit";
    (void)get_instance_file(pathname, filename.c_str());
    file_conn->file.open(pathname,
        (std::ios::out | (cfg.text_format ? (std::ios::openmode)0 : std::ios::binary)) );

    return file_conn;
}

static Connector* file_connector_tinit_receive(std::string& filename, const FileConnectorConfig& cfg)
{
    FileConnector* file_conn = new FileConnector(cfg);
    std::string pathname;

    filename += "_receive";
    (void)get_instance_file(pathname, filename.c_str());
    file_conn->file.open(pathname, (std::ios::in | std::ios::binary) );

    return file_conn;
}

// Create a per-thread object
static Connector* file_connector_tinit(const ConnectorConfig& config)
{
    const FileConnectorConfig& fconf = static_cast<const FileConnectorConfig&>(config);

    std::string filename = FILE_CONNECTOR_NAME;
    filename += "_";
    filename += fconf.name;

    if ( fconf.direction == Connector::CONN_TRANSMIT )
        return file_connector_tinit_transmit(filename, fconf);

    else if ( fconf.direction == Connector::CONN_RECEIVE )
        return file_connector_tinit_receive(filename, fconf);

    return nullptr;
}

static void file_connector_tterm(Connector* connector)
{
    FileConnector* file_conn = (FileConnector*)connector;

    file_conn->file.close();
    delete file_conn;
}

static ConnectorCommon* file_connector_ctor(Module* m)
{
    FileConnectorModule* mod = (FileConnectorModule*)m;

    return new ConnectorCommon(mod->get_and_clear_config());
}

static void file_connector_dtor(ConnectorCommon* c)
{
    delete c;
}

const ConnectorApi file_connector_api =
{
    {
        PT_CONNECTOR,
        sizeof(ConnectorApi),
        CONNECTOR_API_VERSION,
        2,
        API_RESERVED,
        API_OPTIONS,
        FILE_CONNECTOR_NAME,
        FILE_CONNECTOR_HELP,
        mod_ctor,
        mod_dtor
    },
    0,
    nullptr,
    nullptr,
    file_connector_tinit,
    file_connector_tterm,
    file_connector_ctor,
    file_connector_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* file_connector[] =
#endif
{
    &file_connector_api.base,
    nullptr
};

