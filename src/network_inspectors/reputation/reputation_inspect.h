//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

#ifndef REPUTATION_INSPECT_H
#define REPUTATION_INSPECT_H

#include "framework/inspector.h"

#include "reputation_module.h"

class ReputationData
{
public:
    ReputationData() = default;
    ~ReputationData();

    ListFiles list_files;
    uint8_t* reputation_segment = nullptr;
    table_flat_t* ip_list = nullptr;
    int num_entries = 0;
    bool memcap_reached = false;
};

class Reputation : public snort::Inspector
{
public:
    explicit Reputation(ReputationConfig*);
    ~Reputation() override;

    void tinit() override;
    void tterm() override;

    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet*) override
    { }
    bool configure(snort::SnortConfig*) override;
    void install_reload_handler(snort::SnortConfig*) override;

    ReputationData& get_data()
    { return *rep_data; }
    const ReputationConfig& get_config()
    { return config; }
    ReputationData* load_data();

    void swap_thread_data(ReputationData*);
    void swap_data(ReputationData*);

private:
    ReputationConfig config;
    ReputationData* rep_data;
};

#endif

