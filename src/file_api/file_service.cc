//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
 ** 5.25.12 - Initial Source Code. Hui Cao
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_service.h"

#include "main/snort_config.h"
#include "mime/file_mime_process.h"

#include "file_cache.h"
#include "file_capture.h"
#include "file_flows.h"
#include "file_stats.h"

using namespace snort;

bool FileService::file_type_id_enabled = false;
bool FileService::file_signature_enabled = false;
bool FileService::file_capture_enabled = false;
bool FileService::file_processing_initiated = false;

FileCache* FileService::file_cache = nullptr;

void FileService::init()
{
    FileFlows::init();
}

void FileService::post_init()
{
    MimeSession::init();
    FileConfig* conf = get_file_config();

    if (!conf)
        return;

    if (!file_cache)
        file_cache = new FileCache(conf->max_files_cached);

    if (file_capture_enabled)
        FileCapture::init(conf->capture_memcap, conf->capture_block_size);
}

void FileService::close()
{
    if (file_cache)
        delete file_cache;

    MimeSession::exit();
    FileCapture::exit();
}

void FileService::thread_init()
{ file_stats_init(); }

void FileService::thread_term()
{ file_stats_term(); }

void FileService::enable_file_type()
{
    file_type_id_enabled = true;
}

void FileService::enable_file_signature()
{
    file_signature_enabled = true;
}

/* Enable file capture, also enable file signature */
void FileService::enable_file_capture()
{
    file_capture_enabled = true;
    enable_file_signature();
}

bool FileService::is_file_service_enabled()
{
    return (file_type_id_enabled or file_signature_enabled);
}

/* Get maximal file depth based on configuration
 * This function must be called after all file services are configured/enabled.
 */
int64_t FileService::get_max_file_depth()
{
    FileConfig* file_config = get_file_config();

    if (!file_config)
        return -1;

    if (file_config->file_depth)
        return file_config->file_depth;

    file_config->file_depth = -1;

    if (file_type_id_enabled)
    {
        file_config->file_depth = file_config->file_type_depth;
    }

    if (file_signature_enabled)
    {
        if (file_config->file_signature_depth > file_config->file_depth)
            file_config->file_depth = file_config->file_signature_depth;
    }

    if (file_config->file_depth > 0)
    {
        /*Extra byte for deciding whether file data will be over limit*/
        file_config->file_depth++;
        return (file_config->file_depth);
    }
    else
    {
        return -1;
    }
}

namespace snort
{
uint64_t get_file_processed_size(Flow* flow)
{
    FileFlows* file_flows = FileFlows::get_file_flows(flow);

    if (!file_flows)
        return 0;

    FileContext* context = file_flows->get_current_file_context();

    if ( !context )
        return 0;

    return context->get_processed_bytes();
}
}
