//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// rna_module_stubs.h author Masud Hasan <mashasan@cisco.com>

#ifndef RNA_MODULE_TEST_H
#define RNA_MODULE_TEST_H

namespace snort
{
Module* ModuleManager::get_module(const char*)
{ return nullptr; }

char* snort_strdup(const char* s)
{ return strdup(s); }

void Module::sum_stats(bool) {}
void Module::show_stats() {}
void Module::reset_stats() {}
PegCount Module::get_global_count(char const*) const
{ return 0; }
void Module::show_interval_stats(std::vector<unsigned int, std::allocator<unsigned int> >&, FILE*)
{}
void LogMessage(const char*,...) {}
void WarningMessage(const char*,...) {}
DataBus::DataBus() = default;
DataBus::~DataBus() = default;
SnortConfig::SnortConfig(const SnortConfig* const, const char*) {}
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

UaFpProcessor::~UaFpProcessor() = default;
void UaFpProcessor::make_mpse(bool) { }
void UaFpProcessor::push(RawFingerprint const&) { }

void UdpFpProcessor::push(RawFingerprint const&) { }

SmbFingerprint::SmbFingerprint(const RawFingerprint&) { }
bool SmbFingerprint::operator==(const SmbFingerprint&) const { return true; }
bool SmbFpProcessor::push(SmbFingerprint const&) { return true; }
}

void snort::main_broadcast_command(snort::AnalyzerCommand*, ControlConn*) {}

ControlConn* ControlConn::query_from_lua(const lua_State*) { return &s_ctrlcon; }
bool ControlConn::respond(const char*, ...) { return true; }

HostCacheMac* get_host_cache_mac() { return nullptr; }

DataPurgeAC::~DataPurgeAC() = default;
bool DataPurgeAC::execute(Analyzer&, void**) { return true;}

void set_host_cache_mac(HostCacheMac*) { }

Inspector* InspectorManager::get_inspector(const char*, bool, const SnortConfig*)
{
    return nullptr;
}

void HostTracker::remove_flows() { }

#endif
