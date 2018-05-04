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

FileConnectorMsgHandle::FileConnectorMsgHandle(const uint32_t length)
{
    connector_msg.length = length;
    connector_msg.data = new uint8_t[length];
}

FileConnectorMsgHandle::~FileConnectorMsgHandle()
{
    delete[] connector_msg.data;
}

FileConnectorCommon::FileConnectorCommon(FileConnectorConfig::FileConnectorConfigSet* conf)
{
    config_set = (ConnectorConfig::ConfigSet*)conf;
}

FileConnectorCommon::~FileConnectorCommon()
{
    for ( auto conf : *config_set )
    {
        FileConnectorConfig* fconf = (FileConnectorConfig*)conf;
        delete fconf;
    }

    config_set->clear();
    delete config_set;
}

FileConnector::FileConnector(FileConnectorConfig* file_connector_config)
{
    config = file_connector_config;
}

ConnectorMsgHandle* FileConnector::alloc_message(const uint32_t length, const uint8_t** data)
{
    FileConnectorMsgHandle* msg = new FileConnectorMsgHandle(length);

    *data = (uint8_t*)msg->connector_msg.data;

    return msg;
}

void FileConnector::discard_message(ConnectorMsgHandle* msg)
{
    FileConnectorMsgHandle* fmsg = (FileConnectorMsgHandle*)msg;
    delete fmsg;
}

bool FileConnector::transmit_message(ConnectorMsgHandle* msg)
{
    FileConnectorMsgHandle* fmsg = (FileConnectorMsgHandle*)msg;
    const FileConnectorConfig* cfg = (const FileConnectorConfig*)config;

    if ( cfg->text_format )
    {
        unsigned char* message = (unsigned char*)(fmsg->connector_msg.data + sizeof(SCMsgHdr));
        SCMsgHdr* hdr = (SCMsgHdr*)(fmsg->connector_msg.data);

        file << hdr->port << ":" << hdr->time_seconds << "." << hdr->time_u_seconds;

        for ( int i = 0; i<(int)(fmsg->connector_msg.length - sizeof(SCMsgHdr)); i++ )
        {
            char hex_string[4];
            snprintf(hex_string, 4, ",%02X", *message++);
            file << hex_string;
        }

        file << "\n";
    }
    else
    {
        FileConnectorMsgHdr fc_hdr(fmsg->connector_msg.length);

        file.write( (const char*)&fc_hdr, sizeof(fc_hdr) );
        file.write( (const char*)fmsg->connector_msg.data, fmsg->connector_msg.length);
    }

    delete fmsg;

    return true;
}

ConnectorMsgHandle* FileConnector::receive_message_binary()
{
    uint8_t* buffer = new uint8_t[MAXIMUM_SC_MESSAGE_CONTENT+sizeof(SCMsgHdr)+
        sizeof(FileConnectorMsgHdr)];
    // The FileConnectorMsgHdr is at the beginning of the buffer
    FileConnectorMsgHdr* fc_hdr = (FileConnectorMsgHdr*)buffer;

    // Read the FileConnect and SC headers
    file.read((char*)buffer, (sizeof(FileConnectorMsgHdr)+sizeof(SCMsgHdr)));

    // If not present, then no message exists
    if ( (unsigned)file.gcount() < (sizeof(FileConnectorMsgHdr)+sizeof(SCMsgHdr)) )
    {
        delete[] buffer;
        return nullptr;
    }

    // Now read the SC message content
    file.read((char*)(buffer+sizeof(FileConnectorMsgHdr)+sizeof(SCMsgHdr)),
        (fc_hdr->connector_msg_length - sizeof(SCMsgHdr)));

    // If not present, then no valid message exists
    if ( (unsigned)file.gcount() < (fc_hdr->connector_msg_length - sizeof(SCMsgHdr)) )
    {
        delete[] buffer;
        return nullptr;
    }

    // The message is valid, make a ConnectorMsg to contain it.
    FileConnectorMsgHandle* handle = new FileConnectorMsgHandle(fc_hdr->connector_msg_length);

    // Copy the connector message into the new ConnectorMsg
    memcpy(handle->connector_msg.data, (buffer+sizeof(FileConnectorMsgHdr)),
        fc_hdr->connector_msg_length);
    delete[] buffer;

    return handle;
}

ConnectorMsgHandle* FileConnector::receive_message_text()
{
    char line_buffer[4*MAXIMUM_SC_MESSAGE_CONTENT];
    char message[MAXIMUM_SC_MESSAGE_CONTENT];
    char* current = line_buffer;
    uint64_t time_seconds;
    uint32_t time_u_seconds;
    uint16_t port;
    int length = 0;

    // Read the record
    file.getline(line_buffer, sizeof(line_buffer));

    // If not present, then no message exists
    //   (1 for type, 1 for colon, 1 for time, 1 for null)
    if ( (unsigned)file.gcount() < 4 )
    {
        return nullptr;
    }

    // FIXIT-L Add sanity/retval checking for sscanfs below
    sscanf(line_buffer, "%hu:%" SCNu64 ".%" SCNu32, &port, &time_seconds, &time_u_seconds);

    while ( (current = strchr(current,(int)',')) != nullptr )
    {
        current += 1;   // step to the character after the comma
        sscanf(current,"%hhx",(unsigned char*)&(message[length++]));
    }

    // The message is valid, make a ConnectorMsg to contain it.
    FileConnectorMsgHandle* handle = new FileConnectorMsgHandle(length+sizeof(SCMsgHdr));

    // Populate the new message header
    SCMsgHdr* hdr = (SCMsgHdr*) handle->connector_msg.data;
    hdr->port = port;
    hdr->sequence = 0;
    hdr->time_seconds = time_seconds;
    hdr->time_u_seconds = time_u_seconds;
    // Copy the connector message into the new ConnectorMsg
    memcpy((handle->connector_msg.data+sizeof(SCMsgHdr)), message, length);

    return handle;
}

// Reading messages from files can never block.  Either a message exists
//  or it does not.
ConnectorMsgHandle* FileConnector::receive_message(bool)
{
    if ( !file.is_open() )
        return nullptr;
    else
    {
        const FileConnectorConfig* cfg = (const FileConnectorConfig*)config;
        if ( cfg->text_format )
        {
            return( receive_message_text() );
        }
        else
        {
            return( receive_message_binary() );
        }
    }
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

static Connector* file_connector_tinit_transmit(std::string filename,
    FileConnectorConfig* cfg)
{
    FileConnector* file_connector = new FileConnector(cfg);
    std::string pathname;

    filename += "_transmit";
    (void)get_instance_file(pathname, filename.c_str());
    file_connector->file.open(pathname,
        (std::ios::out | (cfg->text_format ? (std::ios::openmode)0 : std::ios::binary)) );

    return file_connector;
}

static Connector* file_connector_tinit_receive(std::string filename,
    FileConnectorConfig* cfg)
{
    FileConnector* file_connector = new FileConnector(cfg);
    std::string pathname;

    filename += "_receive";
    (void)get_instance_file(pathname, filename.c_str());
    file_connector->file.open(pathname, (std::ios::in | std::ios::binary) );

    return file_connector;
}

// Create a per-thread object
static Connector* file_connector_tinit(ConnectorConfig* config)
{
    FileConnectorConfig* cfg = (FileConnectorConfig*)config;

    std::string filename = FILE_CONNECTOR_NAME;
    filename += "_";
    filename += cfg->name;

    if ( cfg->direction == Connector::CONN_TRANSMIT )
        return file_connector_tinit_transmit(filename,cfg);

    else if ( cfg->direction == Connector::CONN_RECEIVE )
        return file_connector_tinit_receive(filename,cfg);

    return nullptr;
}

static void file_connector_tterm(Connector* connector)
{
    FileConnector* file_connector = (FileConnector*)connector;

    file_connector->file.close();
    delete file_connector;
}

static ConnectorCommon* file_connector_ctor(Module* m)
{
    FileConnectorModule* mod = (FileConnectorModule*)m;
    FileConnectorCommon* file_connector_common = new FileConnectorCommon(
        mod->get_and_clear_config());

    return file_connector_common;
}

static void file_connector_dtor(ConnectorCommon* c)
{
    FileConnectorCommon* fc = (FileConnectorCommon*)c;
    delete fc;
}

const ConnectorApi file_connector_api =
{
    {
        PT_CONNECTOR,
        sizeof(ConnectorApi),
        CONNECTOR_API_VERSION,
        0,
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

