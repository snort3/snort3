//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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

// rna_module_mock.h author Masud Hasan <mashasan@cisco.com>

#ifndef RNA_MODULE_MOCK_H
#define RNA_MODULE_MOCK_H

#include "../rna_mac_cache.cc"

THREAD_LOCAL RnaStats rna_stats;
THREAD_LOCAL ProfileStats rna_perf_stats;

namespace snort
{
Module::Module(const char*, const char*, const Parameter*, bool) {}
bool TcpFingerprint::operator==(const TcpFingerprint&) const { return true; }

// inspector
class RnaInspector
{
public:

// The module gets created first, with a mod_conf and fingerprint processor,
// then, when the module is done, we take ownership of that.
RnaInspector(RnaModule* mod)
{
    mod_conf = mod->get_config();
}

~RnaInspector()
{
    if (mod_conf)
    {
        delete mod_conf->tcp_processor;
        delete mod_conf->ua_processor;
        delete mod_conf;
    }
}

TcpFpProcessor* get_fp_processor()
{
    return mod_conf->tcp_processor;
}

private:
    RnaModuleConfig* mod_conf = nullptr;
};

} // end of namespace snort

static ControlConn s_ctrlcon(1, true);
ControlConn::ControlConn(int, bool) {}
ControlConn::~ControlConn() {}

#endif

