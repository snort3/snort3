//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// extractor_quic.cc author Volodymyr Shpyrka <vshpyrka@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_quic.h"

#include <sys/time.h>

#include "detection/detection_engine.h"
#include "flow/flow_key.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "pub_sub/quic_events.h"
#include "utils/util.h"
#include "utils/util_net.h"

#include "extractor.h"
#include "extractor_enums.h"
#include "extractor_flow_data.h"

using namespace snort;
using namespace std;

class QuicExtractorFlowData : public ExtractorFlowData
{
public:
    static constexpr ServiceType type_id = ServiceType::QUIC;

    QuicExtractorFlowData(QuicExtractor& owner)
        : ExtractorFlowData(type_id, owner.get_inspector()), owner(owner) {}
    
    ~QuicExtractorFlowData() override
    {
        if (has_data)
            owner.dump(*this);
    }

    void reset()
    {
        version.clear();
        client_initial_dcid.clear();
        client_scid.clear();
        server_name.clear();
        client_protocol.clear();
        server_scid.clear();
        history.clear();
        ts = {};
        has_data = false;
    }

    std::string version;
    std::string client_initial_dcid;
    std::string client_scid;
    std::string server_name;
    std::string client_protocol;

    std::string server_scid;
    std::string history;

    struct timeval ts = {};

    bool has_data = false;

private:
    QuicExtractor& owner;
};

namespace flow
{
static const char* get_version(const QuicExtractorFlowData& fd)
{
    return fd.version.c_str();
}

static const char* get_client_initial_dcid(const QuicExtractorFlowData& fd)
{
    return fd.client_initial_dcid.c_str();
}

static const char* get_client_scid(const QuicExtractorFlowData& fd)
{
    return fd.client_scid.c_str();
}

static const char* get_server_name(const QuicExtractorFlowData& fd)
{
    return fd.server_name.c_str();
}

static const char* get_client_protocol(const QuicExtractorFlowData& fd)
{
    return fd.client_protocol.c_str();
}

static const char* get_server_scid(const QuicExtractorFlowData& fd)
{
    return fd.server_scid.c_str();
}

static const char* get_history(const QuicExtractorFlowData& fd)
{
    return fd.history.c_str();
}

static const map<string, QuicExtractor::FdStrGetFn> fd_str_getters =
{
    {"version", get_version},
    {"client_initial_dcid", get_client_initial_dcid},
    {"client_scid", get_client_scid},
    {"server_name", get_server_name},
    {"client_protocol", get_client_protocol},
    {"server_scid", get_server_scid},
    {"history", get_history}
};
}

THREAD_LOCAL const snort::Connector::ID* QuicExtractor::log_id = nullptr;

void QuicExtractor::internal_tinit(const snort::Connector::ID* service_id)
{ log_id = service_id; }

QuicExtractor::QuicExtractor(Extractor& extractor, uint32_t tenant, const std::vector<std::string>& fields)
    : ExtractorEvent(ServiceType::QUIC, extractor, tenant)
{
    for (const auto& f : fields)
    {
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
        if (append(fd_str_fields, flow::fd_str_getters, f))
            continue;
    }

    DataBus::subscribe_global(quic_logging_pub_key, QuicLoggingEventIds::QUIC_CLIENT_HELLO_EVENT,
        new ClientHello(*this, S_NAME), extractor.get_snort_config());
    DataBus::subscribe_global(quic_logging_pub_key, QuicLoggingEventIds::QUIC_HANDSHAKE_COMPLETE_EVENT,
        new HandshakeComplete(*this, S_NAME), extractor.get_snort_config());
}

std::vector<const char*> QuicExtractor::get_field_names() const
{
    vector<const char*> res = ExtractorEvent::get_field_names();

    for (auto& f : fd_str_fields)
        res.push_back(f.name);

    return res;
}

template<>
// Passing QuicExtractorFlowData as a pointer.
// Unfortunately, template expansion is confused if we pass an object (a reference).
void ExtractorEvent::log<vector<QuicExtractor::FdStrField>, const QuicExtractorFlowData*>(
    const vector<QuicExtractor::FdStrField>& fields, const QuicExtractorFlowData* fd, bool strict)
{
    for (const auto& f : fields)
    {
        auto d = f.get(*fd);
        if (d && std::strlen(d) > 0)
            logger->add_field(f.name, d);
        else if (strict)
            logger->add_field(f.name, "");
    }
}

void QuicExtractor::dump(const QuicExtractorFlowData& fd)
{
    Profile profile(extractor_perf_stats);

    logger->open_record();

    for (const auto& f : nts_fields)
        logger->add_field(f.name, fd.ts);
    for (const auto& f : sip_fields)
        logger->add_field(f.name, "");
    for (const auto& f : num_fields)
        logger->add_field(f.name, (uint64_t)0);

    log(fd_str_fields, &fd, logger->is_strict());
    
    logger->close_record(*log_id);
}

void QuicExtractor::ClientHello::handle(DataEvent& event, Flow* flow)
{
    Profile profile(extractor_perf_stats);

    if (!owner.filter(flow))
        return;

    extractor_stats.total_events++;
    auto fd = ExtractorFlowData::get<QuicExtractorFlowData>(flow);

    if (!fd)
        flow->set_flow_data(fd = new QuicExtractorFlowData(owner));
    else if (fd->has_data)
    {
        // log existing flow data
        owner.logger->open_record();
        owner.log(owner.nts_fields, &event, flow);
        owner.log(owner.sip_fields, &event, flow);
        owner.log(owner.num_fields, &event, flow);
        owner.log(owner.fd_str_fields, (const QuicExtractorFlowData*)fd, owner.logger->is_strict());
        owner.logger->close_record(*log_id);

        fd->reset();
    }

    const auto& quic_event = static_cast<const QuicClientHelloEvent&>(event);

    fd->version = quic_event.get_version();
    fd->client_initial_dcid = quic_event.get_client_initial_dcid();
    fd->client_scid = quic_event.get_client_scid();
    fd->server_name = quic_event.get_server_name();
    fd->client_protocol = quic_event.get_client_protocol();

    const Packet* packet = ExtractorEvent::get_packet();
    if (packet)
        fd->ts = packet->pkth->ts;
    else
        snort::packet_gettimeofday(&fd->ts);

    fd->has_data = true;
}

void QuicExtractor::HandshakeComplete::handle(DataEvent& event, Flow* flow)
{
    Profile profile(extractor_perf_stats);

    if (!owner.filter(flow))
        return;

    extractor_stats.total_events++;
    auto fd = ExtractorFlowData::get<QuicExtractorFlowData>(flow);

    if (!fd)
        flow->set_flow_data(fd = new QuicExtractorFlowData(owner));

    const auto& quic_event = static_cast<const QuicHandshakeCompleteEvent&>(event);

    fd->server_scid = quic_event.get_server_scid();
    fd->history = quic_event.get_history();

    owner.logger->open_record();
    owner.log(owner.nts_fields, &event, flow);
    owner.log(owner.sip_fields, &event, flow);
    owner.log(owner.num_fields, &event, flow);
    owner.log(owner.fd_str_fields, (const QuicExtractorFlowData*)fd, owner.logger->is_strict());
    owner.logger->close_record(*log_id);

    fd->reset();
}
