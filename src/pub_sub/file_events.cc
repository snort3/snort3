//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// file_events.cc author Shilpa Nagpal <shinagpa@cisco.com>
// Inspection events published by the File Inspector. Modules can subscribe
// to receive the events.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_events.h"

#include <optional>

#include "file_api/file_lib.h"
#include "utils/util.h"

using namespace snort;

uint64_t FileEvent::get_fuid() const
{ return file_ctx.get_file_id(); }

const std::string& FileEvent::get_source() const
{ return file_ctx.get_source(); }

const char* FileEvent::get_mime_type() const
{
    return file_ctx.get_mime_type();
}

const std::string& FileEvent::get_filename() const
{
    if (!filename.has_value())
    {
        size_t fname_len = file_ctx.get_file_name().length();
        filename = std::string();

        if (fname_len)
        {
            char* outbuf = const_cast<FileContext&>(file_ctx).get_UTF8_fname(&fname_len);
            const char* fname = (outbuf != nullptr) ? outbuf : file_ctx.get_file_name().c_str();

            size_t pos = 0;
            while (pos < fname_len)
            {
                if (isprint((int)fname[pos]))
                {
                    (*filename) += fname[pos++];
                }
                else
                {
                    (*filename) += '|';
                    bool add_space = false;
                    while ((pos < fname_len) && !isprint((int)fname[pos]))
                    {
                        if (add_space)
                            (*filename) += ' ';
                        else
                            add_space = true;

                        int ch = 0xff & fname[pos];
                        char buf[3];
                        snprintf(buf, sizeof(buf), "%02X", ch);
                        (*filename) += buf;
                        pos++;
                    }
                    (*filename) += '|';
                }
            }

            snort_free(outbuf);
        }
    }

    return *filename;
}

double FileEvent::get_duration() const
{ return file_ctx.get_duration(); }

bool FileEvent::get_is_orig() const
{ return (file_ctx.get_file_direction() == FILE_UPLOAD); }

uint64_t FileEvent::get_seen_bytes() const
{
    uint64_t processed = file_ctx.get_processed_bytes();
    // After file completes, processed_bytes resets to 0
    // In that case, file_size holds the final processed count
    return (processed > 0) ? processed : file_ctx.get_file_size();
}

uint64_t FileEvent::get_total_bytes() const
{ return file_ctx.get_file_size(); }

bool FileEvent::get_timedout() const
{ return file_ctx.get_timedout(); }

const std::string& FileEvent::get_sha256() const
{
    if (!sha256.has_value())
        sha256 = file_ctx.get_file_sig_sha256() ?
            file_ctx.sha_to_string(file_ctx.get_file_sig_sha256()) : std::string();

    return *sha256;
}

const std::string& FileEvent::get_extracted_name() const
{ return file_ctx.get_extracted_name(); }

bool FileEvent::get_extracted_cutoff() const
{ return file_ctx.get_extracted_cutoff(); }

uint64_t FileEvent::get_extracted_size() const
{ return file_ctx.get_extracted_size(); }
