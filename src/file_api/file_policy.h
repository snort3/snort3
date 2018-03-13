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
//  author Hui Cao <huica@cisco.com>

#ifndef FILE_POLICY_H
#define FILE_POLICY_H

#include <map>
#include <vector>

#include "file_api.h"

namespace snort
{
class FileInfo;
}

struct FileVerdictWhen
{
    uint32_t type_id;
    std::string sha256;
};

struct FileVerdictUse
{
    FileVerdict verdict = FILE_VERDICT_UNKNOWN;
    bool type_enabled = false;
    bool signature_enabled = false;
    bool capture_enabled = false;
};

class FileRule
{
public:
    FileVerdictWhen when;
    FileVerdictUse use;

    FileRule();
    void clear();
};

class FilePolicy: public snort::FilePolicyBase
{
public:

    FilePolicy() = default;
    ~FilePolicy() override = default;

    void policy_check(snort::Flow*, snort::FileInfo*) override;

    // This is called after file type is known
    FileVerdict type_lookup(snort::Flow*, snort::FileInfo*) override;

    // This is called after file signature is complete
    FileVerdict signature_lookup(snort::Flow*, snort::FileInfo*) override;

    void insert_file_rule(FileRule&);
    void set_file_type(bool enabled);
    void set_file_signature(bool enabled);
    void set_file_capture(bool enabled);
    void load();
    void set_verdict_delay(int64_t delay) { verdict_delay = delay; }

private:
    FileRule& match_file_rule(snort::Flow*, snort::FileInfo*);
    FileVerdict match_file_signature(snort::Flow*, snort::FileInfo*);
    std::vector<FileRule> file_rules;
    std::map<std::string, FileVerdict> file_shas;
    bool type_enabled = false;
    bool signature_enabled = false;
    bool capture_enabled = false;
    int64_t verdict_delay = 0;

};

#endif

