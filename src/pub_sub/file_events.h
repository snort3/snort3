//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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

// file_events.h author Shilpa Nagpal <shinagpa@cisco.com>

// File events published by File Service for MP snort support.

#ifndef FILE_EVENTS_H
#define FILE_EVENTS_H

#include <optional>

#include "file_api/file_cache.h"
#include "file_events_ids.h"
#include "framework/mp_data_bus.h"
#include "hash/hashes.h"

namespace snort
{

class SO_PUBLIC FileMPEvent : public snort::DataEvent
{
public:

    FileMPEvent(const FileHashKey& key, int64_t tm, FileInfo& file) : timeout(tm), hashkey(key), file_ctx(file)
    { 
        len = sizeof(timeout) + sizeof(hashkey.sip) + sizeof(hashkey.sgroup)
            + sizeof(hashkey.dip) + sizeof(hashkey.dgroup)
            + sizeof(hashkey.file_id) + sizeof(hashkey.asid) + sizeof(hashkey.padding)
            + sizeof(file) + SHA256_HASH_SIZE;
    }

    FileMPEvent() : hashkey()
    {
        timeout = 0;
        len = 0;
    }

    int64_t get_timeout()
    {
        return timeout;
    }

    FileInfo get_file_ctx()
    {
        return file_ctx;
    }

    FileHashKey get_hashkey()
    {
        return hashkey;
    }

    uint16_t get_data_len()
    {
        return len;
    }

    void deserialize(const char* buffer, uint16_t len)
    {
        uint16_t offset = 0;
        memcpy(&timeout, buffer, sizeof(timeout));
        offset += sizeof(timeout);
        memcpy(&hashkey.sip, buffer + offset, sizeof(hashkey.sip));
        offset += sizeof(hashkey.sip);
        memcpy(&hashkey.sgroup, buffer + offset, sizeof(hashkey.sgroup));
        offset += sizeof(hashkey.sgroup);
        memcpy(&hashkey.dip, buffer + offset, sizeof(hashkey.dip));
        offset += sizeof(hashkey.dip);
        memcpy(&hashkey.dgroup, buffer + offset, sizeof(hashkey.dgroup));
        offset += sizeof(hashkey.dgroup);
        memcpy(&hashkey.file_id, buffer + offset, sizeof(hashkey.file_id));
        offset += sizeof(hashkey.file_id);
        memcpy(&hashkey.asid, buffer + offset, sizeof(hashkey.asid));
        offset += sizeof(hashkey.asid);
        memcpy(&hashkey.padding, buffer + offset, sizeof(hashkey.padding));
        offset += sizeof(hashkey.padding);
        if (offset < len)
            file_ctx.deserialize(buffer + offset, len - offset);
        this->len = len;
    }

    void serialize(char* buffer, uint16_t len)
    {
        uint16_t offset = 0;
        memcpy(buffer, &timeout, sizeof(timeout));
        offset += sizeof(timeout);
        memcpy(buffer + offset, &hashkey.sip, sizeof(hashkey.sip));
        offset += sizeof(hashkey.sip);
        memcpy(buffer + offset, &hashkey.sgroup, sizeof(hashkey.sgroup));
        offset += sizeof(hashkey.sgroup);
        memcpy(buffer + offset, &hashkey.dip, sizeof(hashkey.dip));
        offset += sizeof(hashkey.dip);
        memcpy(buffer + offset, &hashkey.dgroup, sizeof(hashkey.dgroup));
        offset += sizeof(hashkey.dgroup);
        memcpy(buffer + offset, &hashkey.file_id, sizeof(hashkey.file_id));
        offset += sizeof(hashkey.file_id);
        memcpy(buffer + offset, &hashkey.asid, sizeof(hashkey.asid));
        offset += sizeof(hashkey.asid);
        memcpy(buffer + offset, &hashkey.padding, sizeof(hashkey.padding));
        offset += sizeof(hashkey.padding);
        if (offset < len)
            file_ctx.serialize(buffer + offset, len - offset);
    }

private:
    int64_t timeout;
    FileHashKey hashkey;
    FileInfo file_ctx;
    uint16_t len;
};

class SO_PUBLIC FileEvent : public DataEvent
{
public:
    FileEvent(const FileContext& data) : file_ctx(data) { }

    uint64_t get_fuid() const;
    const std::string& get_source() const;
    const char* get_mime_type() const;
    const std::string& get_filename() const;
    double get_duration() const;  // Returns duration in seconds (fractional)
    bool get_is_orig() const;
    uint64_t get_seen_bytes() const;
    uint64_t get_total_bytes() const;
    bool get_timedout() const;
    const std::string& get_sha256() const;
    const std::string& get_extracted_name() const;
    bool get_extracted_cutoff() const;
    uint64_t get_extracted_size() const;

private:
    const FileContext& file_ctx;
    mutable std::optional<std::string> sha256;
    mutable std::optional<std::string> filename;
};

}
#endif
