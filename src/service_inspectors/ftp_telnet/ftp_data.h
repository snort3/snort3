//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#ifndef FTP_DATA_H
#define FTP_DATA_H

#include "framework/inspector.h"
#include "ftp_module.h"

extern const snort::InspectApi fd_api;
#define FTP_DATA_NAME "ftp_data"
#define s_help \
    "FTP data channel handler"

class SO_PUBLIC FtpData : public snort::Inspector
{
public:
    FtpData() = default;

    void eval(snort::Packet*) override;
    snort::StreamSplitter* get_splitter(bool to_server) override;

    bool can_carve_files() const override
    { return true; }

    bool can_start_tls() const override
    { return true; }
};

class FtpDataModule : public snort::Module
{
public:
    FtpDataModule() : snort::Module(FTP_DATA_NAME, s_help) { }

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override
    { return false; }

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }
};

#endif

