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
//
// author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_policy.h"

#include "hash/hashes.h"

#include "file_capture.h"
#include "file_lib.h"
#include "file_service.h"

using namespace snort;

static FileRule emptyRule;

void FileRule::clear()
{
    when.type_id = 0;
    when.sha256.clear();
    use.capture_enabled = false;
    use.signature_enabled = false;
    use.type_enabled = false;
    use.verdict = FILE_VERDICT_UNKNOWN;
}

FileRule::FileRule()
{
    FileRule::clear();
}

void FilePolicy::set_file_type(bool enabled)
{
    type_enabled = enabled;
}

void FilePolicy::set_file_signature(bool enabled)
{
    signature_enabled = enabled;
}

void FilePolicy::set_file_capture(bool enabled)
{
    capture_enabled = enabled;
}

void FilePolicy::insert_file_rule(FileRule& rule)
{
    file_rules.push_back(rule);

    if (!rule.when.sha256.empty())
    {
        size_t offset = 0;

        std::string hex = rule.when.sha256;
        std::string bytes;

        while (offset < hex.size())
        {
            int buffer = std::stoi(hex.substr(offset, 2), nullptr, 16);
            bytes.push_back(static_cast<unsigned char>(buffer));
            offset += 2;
        }

        file_shas[bytes] = rule.use.verdict;
    }

    // Enable file type for all other features
    snort::FileService::enable_file_type();
    type_enabled = true;

    if (rule.use.signature_enabled)
        snort::FileService::enable_file_signature();

    if (rule.use.capture_enabled)
        snort::FileService::enable_file_capture();
}

void FilePolicy::load()
{
    if (type_enabled)
        snort::FileService::enable_file_type();

    if (signature_enabled)
        snort::FileService::enable_file_signature();

    if (capture_enabled)
        snort::FileService::enable_file_capture();

    // Use default global setting
    emptyRule.use.type_enabled = type_enabled;
    emptyRule.use.signature_enabled = signature_enabled;
    emptyRule.use.capture_enabled = capture_enabled;
}

FileRule& FilePolicy::match_file_rule(Flow*, FileInfo* file)
{
    for (unsigned i = 0; i < file_rules.size(); i++)
    {
        if (!file_rules[i].when.sha256.empty())
            continue;
        // No file type specified in rule or file type is matched
        if ((file_rules[i].when.type_id == 0)or
                (file_rules[i].when.type_id == file->get_file_type()))
            return file_rules[i];
    }

    return emptyRule;
}

FileVerdict FilePolicy::match_file_signature(Flow*, FileInfo* file)
{
    // No file type specified in rule or file type is matched
    if (file->get_file_sig_sha256())
    {
        std::string sha((const char*)file->get_file_sig_sha256(), SHA256_HASH_SIZE);

        auto search = file_shas.find(sha);
        if (search != file_shas.end())
        {
            if (verdict_delay > 0)
            {
                verdict_delay--;
                return FILE_VERDICT_PENDING;
            }
            else
                return search->second;
        }
    }

    return FILE_VERDICT_UNKNOWN;
}

void FilePolicy::policy_check(Flow*, FileInfo* file)
{
    // TODO: enable based on file policy rules on flow
    file->config_file_type(type_enabled);
    file->config_file_signature(signature_enabled);
    file->config_file_capture(capture_enabled);
}

FileVerdict FilePolicy::type_lookup(Flow*, FileInfo* file)
{
    FileRule rule = match_file_rule(nullptr, file);
    file->config_file_signature(rule.use.signature_enabled);
    file->config_file_capture(rule.use.capture_enabled);
    return rule.use.verdict;
}

FileVerdict FilePolicy::signature_lookup(Flow*, FileInfo* file)
{
    FileRule& rule = match_file_rule(nullptr, file);

    if (rule.use.capture_enabled)
    {
        FileCapture* captured = nullptr;

        if (file->reserve_file(captured) == FILE_CAPTURE_SUCCESS)
            captured->store_file_async();
        else
            delete captured;
    }

    return match_file_signature(nullptr, file);
}
