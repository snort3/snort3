//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// stubs.h author Ron Dempster <rdempste@cisco.com>

#include "detection/context_switcher.h"
#include "detection/detection_engine.h"
#include "detection/detection_util.h"
#include "detection/ips_context.h"
#include "detection/tag.h"
#include "file_api/file_service.h"
#include "filters/detection_filter.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "filters/sfthreshold.h"
#include "flow/ha.h"
#include "framework/data_bus.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency.h"
#include "log/messages.h"
#include "managers/action_manager.h"
#include "managers/codec_manager.h"
#include "managers/event_manager.h"
#include "managers/inspector_manager.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "main.h"
#include "main/analyzer.h"
#include "main/oops_handler.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "main/swapper.h"
#include "main/thread_config.h"
#include "network_inspectors/packet_tracer/packet_tracer.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_module.h"
#include "profiler/profiler.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"
#include "side_channel/side_channel.h"
#include "stream/stream.h"
#include "target_based/host_attributes.h"
#include "time/packet_time.h"
#include "trace/trace_api.h"
#include "utils/dnet_header.h"
#include "utils/stats.h"

THREAD_LOCAL DAQStats daq_stats;

void Profiler::start() { }
void Profiler::stop(uint64_t) { }
void Profiler::consolidate_stats() { }
void Swapper::apply(Analyzer&) { }
Swapper::~Swapper() = default;
void OopsHandler::tinit() { }
void OopsHandler::tterm() { }
uint16_t get_run_num() { return 0; }
void set_run_num(uint16_t) { }
void set_instance_id(unsigned) { }
void set_thread_type(SThreadType) { }
void ContextSwitcher::push(snort::IpsContext*) { }
void ContextSwitcher::stop() { }
ContextSwitcher::~ContextSwitcher() = default;
snort::IpsContext* ContextSwitcher::get_context() const { return nullptr; }
void ContextSwitcher::start() { }
void InitTag() { }
void CleanupTag() { }
void RateFilter_Cleanup() { }
int sfthreshold_alloc(unsigned int, unsigned int) { return -1; }
void sfthreshold_reset() { }
void sfthreshold_free() { }
void EventTrace_Init() { }
void EventTrace_Term() { }
void detection_filter_init(DetectionFilterConfig*) { }
void detection_filter_term() { }
void RuleLatency::tterm() { }
void PacketLatency::tterm() { }
void SideChannelManager::thread_init() { }
void SideChannelManager::thread_term() { }
void CodecManager::thread_init(const snort::SnortConfig*) { }
void CodecManager::thread_term() { }
void EventManager::open_outputs() { }
void EventManager::close_outputs() { }
void IpsManager::setup_options(const snort::SnortConfig*) { }
void IpsManager::clear_options(const snort::SnortConfig*) { }
void ActionManager::thread_init(const snort::SnortConfig*) { }
void ActionManager::thread_term() { }
void ActionManager::thread_reinit(const snort::SnortConfig*) { }
int SFRF_Alloc(unsigned int) { return -1; }
void packet_time_update(const struct timeval*) { }
void main_poke(unsigned) { }
void set_default_policy(const snort::SnortConfig*) { }
bool snort_ignore(snort::Packet*) { return false; }
ip_t* ip_open() { return nullptr; }
ip_t* ip_close(ip_t*) { return nullptr; }
ssize_t ip_send(ip_t*, const void*, size_t) { return -1; }
eth_t* eth_open(const char*) { return nullptr; }
eth_t* eth_close(eth_t*) { return nullptr; }
ssize_t eth_send(eth_t*, const void*, size_t) { return -1; }
void HostAttributesManager::initialize() { }

void select_default_policy(const _daq_pkt_hdr&, const snort::SnortConfig*) { }
void select_default_policy(const _daq_flow_stats&, const snort::SnortConfig*) { }

namespace snort
{
static struct timeval s_packet_time = { 0, 0 };
THREAD_LOCAL PacketTracer* s_pkt_trace;
THREAD_LOCAL TimeContext* ProfileContext::curr_time = nullptr;
bool TimeProfilerStats::enabled = false;
THREAD_LOCAL PacketCount pc;

void packet_gettimeofday(struct timeval* tv) { *tv = s_packet_time; }
MemoryContext::MemoryContext(MemoryTracker&) : saved(nullptr) { }
MemoryContext::~MemoryContext() = default;
Packet::Packet(bool)
{
    memset(this , 0, sizeof(*this));
    ip_proto_next = IpProtocol::PROTO_NOT_SET;
    packet_flags = PKT_FROM_CLIENT;
}
Packet::~Packet()  = default;
IpsPolicy* get_ips_policy() { return nullptr; }
void DataBus::publish(const char*, Packet*, Flow*) { }
void DataBus::publish(const char*, DataEvent&, Flow*) { }
SFDAQInstance::SFDAQInstance(const char*, unsigned, const SFDAQConfig*) { }
SFDAQInstance::~SFDAQInstance() = default;
void SFDAQInstance::reload() { }
bool SFDAQInstance::start() { return false; }
bool SFDAQInstance::stop() { return false; }
const char* SFDAQInstance::get_error() { return nullptr; }
bool SFDAQInstance::interrupt() { return false; }
int SFDAQInstance::inject(DAQ_Msg_h, int, const uint8_t*, uint32_t) { return -1; }
DAQ_RecvStatus SFDAQInstance::receive_messages(unsigned) { return DAQ_RSTAT_ERROR; }
int SFDAQInstance::ioctl(DAQ_IoctlCmd, void*, size_t) { return -4; }
void SFDAQ::set_local_instance(SFDAQInstance*) { }
const char* SFDAQ::verdict_to_string(DAQ_Verdict) { return nullptr; }
bool SFDAQ::forwarding_packet(const DAQ_PktHdr_t*) { return false; }
int SFDAQ::inject(DAQ_Msg_h, int, const uint8_t*, uint32_t) { return -1; }
bool SFDAQ::can_inject() { return false; }
bool SFDAQ::can_inject_raw() { return false; }
int SFDAQInstance::set_packet_verdict_reason(DAQ_Msg_h, uint8_t) { return 0; }
DetectionEngine::DetectionEngine() = default;
DetectionEngine::~DetectionEngine() = default;
void DetectionEngine::onload() { }
void DetectionEngine::thread_init() { }
void DetectionEngine::thread_term() { }
void DetectionEngine::idle() { }
void DetectionEngine::reset() { }
void DetectionEngine::wait_for_context() { }
void DetectionEngine::set_file_data(const DataPointer&) { }
void DetectionEngine::clear_replacement() { }
void DetectionEngine::disable_all(Packet*) { }
unsigned get_instance_id() { return 0; }
const SnortConfig* SnortConfig::get_conf() { return nullptr; }
void SnortConfig::update_thread_reload_id() { }
void PacketTracer::thread_init() { }
void PacketTracer::thread_term() { }
void PacketTracer::log(const char*, ...) { }
void PacketTracer::dump(Packet*) { }
void PacketTracer::daq_dump(Packet*) { }
void PacketTracer::activate(const Packet&) { }
void TraceApi::thread_init(const TraceConfig*) { }
void TraceApi::thread_term() { }
void TraceApi::thread_reinit(const TraceConfig*) { }
void PacketManager::thread_init() { }
void PacketManager::decode(
    Packet*, const DAQ_PktHdr_t*, const uint8_t*, uint32_t, bool, bool) { }
void PacketManager::encode_update(Packet*) { }
void PacketManager::thread_term() { }
const uint8_t* PacketManager::encode_response(TcpResponse, EncodeFlags, const Packet*, uint32_t&,
    const uint8_t* const, uint32_t) { return nullptr; }
uint16_t PacketManager::encode_get_max_payload(const Packet*) { return 0; }
const uint8_t* PacketManager::encode_reject(UnreachResponse, EncodeFlags, const Packet*, uint32_t&)
{ return nullptr; }
void FileService::thread_init() { }
void FileService::thread_term() { }
void ErrorMessage(const char*,...) { }
void LogMessage(const char*,...) { }
[[noreturn]] void FatalError(const char*,...) { exit(-1); }
void ParseWarning(WarningGroup, const char*, ...) { }
void HighAvailabilityManager::thread_init() { }
void HighAvailabilityManager::process_receive() { }
void HighAvailabilityManager::thread_term() { }
void HighAvailabilityManager::thread_term_beginning() { }
void HighAvailabilityManager::process_update(Flow*, Packet*) { }
void InspectorManager::thread_init(const SnortConfig*) { }
void InspectorManager::thread_term() { }
void InspectorManager::thread_stop(const SnortConfig*) { }
void InspectorManager::thread_reinit(const SnortConfig*) { }
void InspectorManager::thread_stop_removed(const SnortConfig*) { }
void ModuleManager::accumulate() { }
void ModuleManager::accumulate_module(const char*) { }
void Stream::handle_timeouts(bool) { }
void Stream::purge_flows() { }
bool Stream::set_packet_action_to_hold(Packet*) { return false; }
void Stream::init_active_response(const Packet*, Flow*) { }
void Stream::drop_flow(const Packet* ) { }
void Stream::block_flow(const Packet*) { }
IpsContext::IpsContext(unsigned) { }
NetworkPolicy* get_network_policy() { return nullptr; }
InspectionPolicy* get_inspection_policy() { return nullptr; }
Flow::Flow() = default;
Flow::~Flow() = default;
void ThreadConfig::implement_thread_affinity(SThreadType, unsigned) { }
}

namespace memory
{
void MemoryCap::free_space() { }
}
