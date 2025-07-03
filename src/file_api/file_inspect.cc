//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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
/*
 ** Author(s):  Hui Cao <huica@cisco.com>
 **
 ** NOTES
 ** 8.15.15 - Initial Source Code. Hui Cao
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_inspect.h"

#include "log/messages.h"

#include "file_cache.h"
#include "file_config.h"
#include "file_flows.h"
#include "file_module.h"
#include "file_service.h"
#include "file_cache_share.h"

using namespace snort;

FileInspect::FileInspect(FileIdModule* fm)
{
    fm->load_config(config);
}

FileInspect:: ~FileInspect()
{
    if (config)
        delete config;
}

bool FileInspect::configure(SnortConfig* sc)
{
    if (!config)
        return true;

    FileCache* file_cache = FileService::get_file_cache();
    if (file_cache)
    {
        file_cache->set_block_timeout(config->file_block_timeout);
        file_cache->set_lookup_timeout(config->file_lookup_timeout);
        file_cache->set_max_files(config->max_files_cached);
    }

    FileService::set_max_file_depth(sc);

    if(sc->mp_dbus)
    {
        MPSerializeFunc serialize_func = serialize_file_event;
        MPDeserializeFunc deserialize_func = deserialize_file_event;

        MPDataBus::register_event_helpers(file_pub_key, FileMPEvents::FILE_SHARE_SYNC, serialize_func, deserialize_func);
        MPDataBus::subscribe(file_pub_key, FileMPEvents::FILE_SHARE_SYNC, new FileCacheShare(this));
    }
    return true;
}

static void file_config_show(const FileConfig* fc)
{
    if ( ConfigLogger::log_flag("enable_type", FileService::is_file_type_id_enabled()) )
        ConfigLogger::log_value("type_depth", fc->file_type_depth);

    if ( ConfigLogger::log_flag("enable_signature", FileService::is_file_signature_enabled()) )
        ConfigLogger::log_value("signature_depth", fc->file_signature_depth);

    if ( ConfigLogger::log_flag("block_timeout_lookup", fc->block_timeout_lookup) )
        ConfigLogger::log_value("block_timeout", fc->file_block_timeout);

    if ( ConfigLogger::log_flag("enable_capture", FileService::is_file_capture_enabled()) )
    {
        ConfigLogger::log_value("capture_memcap", fc->capture_memcap);
        ConfigLogger::log_value("capture_max_size", fc->capture_max_size);
        ConfigLogger::log_value("capture_min_size", fc->capture_min_size);
        ConfigLogger::log_value("capture_block_size", fc->capture_block_size);
    }

    ConfigLogger::log_value("lookup_timeout", fc->file_lookup_timeout);
    ConfigLogger::log_value("max_files_cached", fc->max_files_cached);
    ConfigLogger::log_value("max_files_per_flow", fc->max_files_per_flow);
    ConfigLogger::log_value("show_data_depth", fc->show_data_depth);

    ConfigLogger::log_flag("trace_type", fc->trace_type);
    ConfigLogger::log_flag("trace_signature", fc->trace_signature);
    ConfigLogger::log_flag("trace_stream", fc->trace_stream);
}

void FileInspect::show(const SnortConfig*) const
{
    if ( config )
        file_config_show(config);
}

static Module* mod_ctor()
{ return new FileIdModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void file_init()
{
    FileFlows::init();
}

static Inspector* file_ctor(Module* m)
{
    FileIdModule* mod = (FileIdModule*)m;
    return new FileInspect(mod);
}

static void file_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi file_inspect_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        FILE_ID_NAME,
        FILE_ID_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_FILE,
    PROTO_BIT__NONE,
    nullptr,
    "file",
    file_init,
    nullptr,
    nullptr, // tinit
    nullptr, // tterm
    file_ctor,
    file_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* sin_file_flow = &file_inspect_api.base;

