//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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

// rna_inspector.h author Masud Hasan <mashasan@cisco.com>

#ifndef RNA_INSPECTOR_H
#define RNA_INSPECTOR_H

#include "framework/inspector.h"

#include <string>

namespace snort
{
struct Packet;
class TcpFpProcessor;
class UaFpProcessor;
class UdpFpProcessor;
class SmbFpProcessor;
}

struct RnaConfig;
class RnaModule;
struct RnaModuleConfig;
class RnaPnd;

class SO_PUBLIC RnaInspector : public snort::Inspector
{
public:
    RnaInspector(RnaModule*);
    ~RnaInspector() override;

    bool configure(snort::SnortConfig*) override;
    void install_reload_handler(snort::SnortConfig*) override;
    void eval(snort::Packet*) override;
    void show(const snort::SnortConfig*) const override;
    void tinit() override;
    void tterm() override;

    void get_or_create_fp_processor(snort::TcpFpProcessor*&, snort::UaFpProcessor*&,
        snort::UdpFpProcessor*&, snort::SmbFpProcessor*&);
    void set_fp_processor(snort::TcpFpProcessor*, snort::UaFpProcessor*,
        snort::UdpFpProcessor*, snort::SmbFpProcessor*);

    RnaPnd* get_pnd() const { return pnd; }

private:
    void load_rna_conf();
    RnaModuleConfig* mod_conf = nullptr;
    RnaConfig* rna_conf = nullptr;
    RnaPnd* pnd = nullptr;
};

#endif
