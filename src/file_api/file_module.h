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

// file_module.h author Hui Cao <huica@cisco.com>

#ifndef FILE_MODULE_H
#define FILE_MODULE_H

#include "framework/module.h"

#include "file_config.h"
#include "file_identifier.h"
#include "file_policy.h"

//-------------------------------------------------------------------------
// file_id module
//-------------------------------------------------------------------------

class FileIdModule : public snort::Module
{
public:
    FileIdModule();
    ~FileIdModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    void sum_stats(bool) override;

    void load_config(FileConfig*& dst);

    Usage get_usage() const override
    { return GLOBAL; }

    void show_dynamic_stats() override;

    // FIXIT-L delete file_id gid when bogus rules are eliminated
    // (this ensures those rules don't fire on every packet)
    unsigned get_gid() const override
    { return 146; }

private:
    FileMagicRule rule;
    FileMagicData magic;
    FileRule file_rule;
    FileConfig *fc = nullptr;
};

#endif

