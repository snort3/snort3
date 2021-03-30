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

#include "main/request.h"

#include "../rna_mac_cache.cc"

THREAD_LOCAL RnaStats rna_stats;
THREAD_LOCAL ProfileStats rna_perf_stats;

const char* luaL_optlstring(lua_State*, int, const char*, size_t*) { return nullptr; }

extern "C"
{
    lua_Number luaL_optnumber(lua_State*, int, lua_Number) { return 0; }
}

namespace snort
{
Module* ModuleManager::get_module(const char*)
{ return nullptr; }

char* snort_strdup(const char* s)
{ return strdup(s); }

Module::Module(const char*, const char*, const Parameter*, bool) {}
void Module::sum_stats(bool) {}
void Module::show_stats() {}
void Module::reset_stats() {}
PegCount Module::get_global_count(char const*) const
{ return 0; }
void Module::show_interval_stats(std::vector<unsigned int, std::allocator<unsigned int> >&, FILE*)
{}
void LogMessage(const char*,...) {}
void WarningMessage(const char*,...) {}
SnortConfig::SnortConfig(SnortConfig const*) {}
SnortConfig::~SnortConfig() = default;
time_t packet_time() { return 0; }

// tcp fingerprint functions
bool TcpFpProcessor::push(const TcpFingerprint&) { return true; }
void TcpFpProcessor::make_tcp_fp_tables(TCP_FP_MODE) { }
const TcpFingerprint* TcpFpProcessor::get_tcp_fp(const FpTcpKey&, uint8_t, TCP_FP_MODE) const
{ return nullptr; }
const TcpFingerprint* TcpFpProcessor::get(const Packet*, RNAFlow*) const
{ return nullptr; }
TcpFpProcessor* get_tcp_fp_processor() { return nullptr; }
void set_tcp_fp_processor(TcpFpProcessor*) { }

TcpFingerprint::TcpFingerprint(const RawFingerprint&) { }
bool TcpFingerprint::operator==(const TcpFingerprint&) const { return true; }

UaFpProcessor::~UaFpProcessor() = default;
void UaFpProcessor::make_mpse(SnortConfig*) { }
void UaFpProcessor::push(RawFingerprint const&) { }

void UdpFpProcessor::push(RawFingerprint const&) { }

SmbFingerprint::SmbFingerprint(const RawFingerprint&) { }
bool SmbFingerprint::operator==(const SmbFingerprint&) const { return true; }
bool SmbFpProcessor::push(SmbFingerprint const&) { return true; }

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

static SharedRequest mock_request = std::make_shared<Request>();
void Request::respond(const char*, bool, bool) { }
SharedRequest get_dispatched_request() { return mock_request; }

HostCacheMac* get_host_cache_mac() { return nullptr; }

DataPurgeAC::~DataPurgeAC() = default;
bool DataPurgeAC::execute(Analyzer&, void**) { return true;}

void snort::main_broadcast_command(AnalyzerCommand*, bool) { }
void set_host_cache_mac(HostCacheMac*) { }

Inspector* InspectorManager::get_inspector(const char*, bool, const SnortConfig*)
{
    return nullptr;
}

void HostTracker::remove_flows() { }

#endif
