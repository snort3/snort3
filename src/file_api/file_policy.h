//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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
    ~FileRule() { }
    void clear();
};

class FileInfo;

class FilePolicy
{
public:
    FilePolicy() { }
    ~FilePolicy() { }

    // This is called when a new flow is queried for the first time
    // Check & update what file policy is enabled on this flow/file
    void policy_check(Flow* flow, FileContext* file);

    // This is called after file type is known
    virtual FileVerdict type_lookup(Flow* flow, FileContext* file);

    // This is called after file type is known
    virtual FileVerdict type_lookup(Flow* flow, FileInfo* file);

    // This is called after file signature is complete
    virtual FileVerdict signature_lookup(Flow* flow, FileContext* file);

    // This is called after file signature is complete
    virtual FileVerdict signature_lookup(Flow* flow, FileInfo* file);

    void insert_file_rule(FileRule&);
    void set_file_type(bool enabled);
    void set_file_signature(bool enabled);
    void set_file_capture(bool enabled);
    bool is_type_id_enabled() { return type_enabled; }
    bool is_signature_enabled() { return signature_enabled; }
    bool is_capture_enabled() { return capture_enabled; }
    void load();

private:
    FileRule& match_file_rule(Flow*, FileInfo* file);
    FileVerdict match_file_signature(Flow*, FileInfo* file);
    std::vector<FileRule> file_rules;
    std::map<std::string, FileVerdict> file_shas;
    bool type_enabled = false;
    bool signature_enabled = false;
    bool capture_enabled = false;
};

#endif

