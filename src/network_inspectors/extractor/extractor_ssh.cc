//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// extractor_ssh.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_ssh.h"

#include <string>

#include "profiler/profiler.h"
#include "pub_sub/ssh_events.h"

#include "extractor.h"
#include "extractor_enums.h"
#include "extractor_flow_data.h"

using namespace snort;
using namespace std;

static void trim(string& str)
{
    str.erase(str.find_last_not_of(" \n\r\t") + 1);
}

template<uint8_t T>
static const char* get_c2s_cipher(const DataEvent* event, const Flow*)
{
    auto e = (const SshAlgoEvent*)event;
    return T == e->get_direction() ? e->get_encryption_algorithms_client_to_server() : "";
}

template<uint8_t T>
static const char* get_s2c_cipher(const DataEvent* event, const Flow*)
{
    auto e = (const SshAlgoEvent*)event;
    return T == e->get_direction() ? e->get_encryption_algorithms_server_to_client() : "";
}

template<uint8_t T>
static const char* get_c2s_mac(const DataEvent* event, const Flow*)
{
    auto e = (const SshAlgoEvent*)event;
    return T == e->get_direction() ? e->get_mac_algorithms_client_to_server() : "";
}

template<uint8_t T>
static const char* get_s2c_mac(const DataEvent* event, const Flow*)
{
    auto e = (const SshAlgoEvent*)event;
    return T == e->get_direction() ? e->get_mac_algorithms_server_to_client() : "";
}

template<uint8_t T>
static const char* get_c2s_compression(const DataEvent* event, const Flow*)
{
    auto e = (const SshAlgoEvent*)event;
    return T == e->get_direction() ? e->get_compression_algorithms_client_to_server() : "";
}

template<uint8_t T>
static const char* get_s2c_compression(const DataEvent* event, const Flow*)
{
    auto e = (const SshAlgoEvent*)event;
    return T == e->get_direction() ? e->get_compression_algorithms_server_to_client() : "";
}

template<uint8_t T>
static const char* get_kex(const DataEvent* event, const Flow*)
{
    auto e = (const SshAlgoEvent*)event;
    return T == e->get_direction() ? e->get_kex_algorithms() : "";
}

template<uint8_t T>
static const char* get_host_key(const DataEvent* event, const Flow*)
{
    auto e = (const SshAlgoEvent*)event;
    return T == e->get_direction() ? e->get_server_host_key_algorithms() : "";
}

static const map<string, ExtractorEvent::BufGetFn> buf_getters =
{
    {"client.kex_alg", get_kex<PKT_FROM_CLIENT>},
    {"client.host_key_alg", get_host_key<PKT_FROM_CLIENT>},
    {"client.cipher_c2s_alg", get_c2s_cipher<PKT_FROM_CLIENT>},
    {"client.cipher_s2c_alg", get_s2c_cipher<PKT_FROM_CLIENT>},
    {"client.mac_c2s_alg", get_c2s_mac<PKT_FROM_CLIENT>},
    {"client.mac_s2c_alg", get_s2c_mac<PKT_FROM_CLIENT>},
    {"client.compression_c2s_alg", get_c2s_compression<PKT_FROM_CLIENT>},
    {"client.compression_s2c_alg", get_s2c_compression<PKT_FROM_CLIENT>},
    {"server.kex_alg", get_kex<PKT_FROM_SERVER>},
    {"server.host_key_alg", get_host_key<PKT_FROM_SERVER>},
    {"server.cipher_c2s_alg", get_c2s_cipher<PKT_FROM_SERVER>},
    {"server.cipher_s2c_alg", get_s2c_cipher<PKT_FROM_SERVER>},
    {"server.mac_c2s_alg", get_c2s_mac<PKT_FROM_SERVER>},
    {"server.mac_s2c_alg", get_s2c_mac<PKT_FROM_SERVER>},
    {"server.compression_c2s_alg", get_c2s_compression<PKT_FROM_SERVER>},
    {"server.compression_s2c_alg", get_s2c_compression<PKT_FROM_SERVER>}
};

static std::string next_item(const char*& ptr)
{
    if (*ptr == '\0')
        return "";

    const char* start = ptr;
    while (*ptr != '\0' and *ptr != ',')
        ptr++;

    std::string item(start, ptr - start);

    if (*ptr == ',')
        ptr++;

    return item;
}

static std::string match(const char* client_list, const char* server_list)
{
    if (!client_list || !server_list)
        return "";

    const char* client_ptr = client_list;

    while (*client_ptr != '\0')
    {
        std::string client_item = next_item(client_ptr);

        const char* server_ptr = server_list;

        while (*server_ptr != '\0')
        {
            std::string server_item = next_item(server_ptr);

            if (client_item == server_item)
                return client_item;
        }
    }

    return "";
}

static std::string match(const std::string& client_list, const char* server_list)
{
    return match(client_list.c_str(), server_list);
}

static std::string match(const char* client_list, const std::string& server_list)
{
    return match(client_list, server_list.c_str());
}

class SshExtractorFlowData : public ExtractorFlowData
{
public:
    static constexpr ServiceType type_id = ServiceType::SSH;

    SshExtractorFlowData(SshExtractor& owner)
        : ExtractorFlowData(type_id), owner(owner) {}

    ~SshExtractorFlowData() override
    {
        half_reset();

        if (event_version_direction or event_validation_direction)
            owner.dump(*this);
    }

    void reset();
    void half_reset();

    string cipher_c2s;
    string cipher_s2c;
    string mac_c2s;
    string mac_s2c;
    string comp_c2s;
    string comp_s2c;
    string kex;
    string host;
    string version_c2s;
    string version_s2c;
    struct timeval ts = {};
    const char* direction = "";
    uint8_t version = 0;
    uint8_t event_version_direction = 0;
    uint8_t event_validation_direction = 0;

    void merge_with_client(const SshAlgoEvent& event)
    {
        cipher_c2s = match(event.get_encryption_algorithms_client_to_server(), cipher_c2s);
        cipher_s2c = match(event.get_encryption_algorithms_server_to_client(), cipher_s2c);
        mac_c2s = match(event.get_mac_algorithms_client_to_server(), mac_c2s);
        mac_s2c = match(event.get_mac_algorithms_server_to_client(), mac_s2c);
        comp_c2s = match(event.get_compression_algorithms_client_to_server(), comp_c2s);
        comp_s2c = match(event.get_compression_algorithms_server_to_client(), comp_s2c);
        kex = match(event.get_kex_algorithms(), kex);
        host = match(event.get_server_host_key_algorithms(), host);

        merge();
    }

    void merge_with_server(const SshAlgoEvent& event)
    {
        cipher_c2s = match(cipher_c2s, event.get_encryption_algorithms_client_to_server());
        cipher_s2c = match(cipher_s2c, event.get_encryption_algorithms_server_to_client());
        mac_c2s = match(mac_c2s, event.get_mac_algorithms_client_to_server());
        mac_s2c = match(mac_s2c, event.get_mac_algorithms_server_to_client());
        comp_c2s = match(comp_c2s, event.get_compression_algorithms_client_to_server());
        comp_s2c = match(comp_s2c, event.get_compression_algorithms_server_to_client());
        kex = match(kex, event.get_kex_algorithms());
        host = match(host, event.get_server_host_key_algorithms());

        merge();
    }

private:
    void merge()
    {
        if (cipher_c2s != cipher_s2c)
            cipher_c2s += "," + cipher_s2c;
        if (mac_c2s != mac_s2c)
            mac_c2s += "," + mac_s2c;
        if (comp_c2s != comp_s2c)
            comp_c2s += "," + comp_s2c;
    }

    SshExtractor& owner;
};

static uint64_t get_version(const SshExtractorFlowData& fd)
{
    return fd.version;
}

static const char* get_direction(const SshExtractorFlowData& fd)
{
    return fd.direction;
}

static const char* get_client_version(const SshExtractorFlowData& fd)
{
    return fd.version_c2s.c_str();
}

static const char* get_server_version(const SshExtractorFlowData& fd)
{
    return fd.version_s2c.c_str();
}

static const char* get_cipher_alg(const SshExtractorFlowData& fd)
{
    return fd.cipher_c2s.c_str();
}

static const char* get_mac_alg(const SshExtractorFlowData& fd)
{
    return fd.mac_c2s.c_str();
}

static const char* get_compression_alg(const SshExtractorFlowData& fd)
{
    return fd.comp_c2s.c_str();
}

static const char* get_kex_alg(const SshExtractorFlowData& fd)
{
    return fd.kex.c_str();
}

static const char* get_host_key_alg(const SshExtractorFlowData& fd)
{
    return fd.host.c_str();
}

static const map<string, SshExtractor::FdNumGetFn> fd_num_getters =
{
    {"version", get_version}
};

static const map<string, SshExtractor::FdBufGetFn> fd_buf_getters =
{
    {"direction", get_direction},
    {"client.version", get_client_version},
    {"server.version", get_server_version},
    {"cipher_alg", get_cipher_alg},
    {"mac_alg", get_mac_alg},
    {"compression_alg", get_compression_alg},
    {"kex_alg", get_kex_alg},
    {"host_key_alg", get_host_key_alg}
};

THREAD_LOCAL const snort::Connector::ID* SshExtractor::log_id = nullptr;

SshExtractor::SshExtractor(Extractor& i, uint32_t t, const vector<string>& fields, bool detailed) :
    ExtractorEvent(ServiceType::SSH, i, t)
{
    for (const auto& f : fields)
    {
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
        if (append(buf_fields, buf_getters, f))
            continue;
        if (append(fd_num_fields, fd_num_getters, f))
            continue;
        if (append(fd_buf_fields, fd_buf_getters, f))
            continue;
    }

    DataBus::subscribe_global(ssh_pub_key, SshEventIds::STATE_CHANGE,
        new Version(*this, S_NAME), i.get_snort_config());
    DataBus::subscribe_global(ssh_pub_key, SshEventIds::ALGORITHM,
        new Validation(*this, S_NAME, detailed), i.get_snort_config());
}

void SshExtractor::internal_tinit(const snort::Connector::ID* service_id)
{ log_id = service_id; }

vector<const char*> SshExtractor::get_field_names() const
{
    vector<const char*> res = ExtractorEvent::get_field_names();

    for (auto& f : fd_num_fields)
        res.push_back(f.name);

    for (auto& f : fd_buf_fields)
        res.push_back(f.name);

    return res;
}

void SshExtractorFlowData::reset()
{
    cipher_c2s.clear();
    cipher_s2c.clear();
    mac_c2s.clear();
    mac_s2c.clear();
    comp_c2s.clear();
    comp_s2c.clear();
    kex.clear();
    host.clear();
    version_c2s.clear();
    version_s2c.clear();
    ts = {};
    direction = "";
    version = 0;
    event_version_direction = 0;
    event_validation_direction = 0;
}

void SshExtractorFlowData::half_reset()
{
    cipher_c2s.clear();
    cipher_s2c.clear();
    mac_c2s.clear();
    mac_s2c.clear();
    comp_c2s.clear();
    comp_s2c.clear();
    kex.clear();
    host.clear();
}

template<>
// Passing SshExtractorFlowData as a pointer.
// Unfortunately, template expansion is confused if we pass an object (a reference).
void ExtractorEvent::log<vector<SshExtractor::FdNumField>, const SshExtractorFlowData*>(
    const vector<SshExtractor::FdNumField>& fields, const SshExtractorFlowData* fd)
{
    for (const auto& f : fields)
    {
        auto d = f.get(*fd);
        logger->add_field(f.name, d);
    }
}

template<>
// Passing SshExtractorFlowData as a pointer.
// Unfortunately, template expansion is confused if we pass an object (a reference).
void ExtractorEvent::log<vector<SshExtractor::FdBufField>, const SshExtractorFlowData*>(
    const vector<SshExtractor::FdBufField>& fields, const SshExtractorFlowData* fd)
{
    for (const auto& f : fields)
    {
        auto d = f.get(*fd);
        logger->add_field(f.name, d);
    }
}

void SshExtractor::Version::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    const SshEvent& ssh_event = *((SshEvent*)&event);

    if (ssh_event.get_event_type() != SSH_VERSION_STRING)
        return;

    if (!owner.filter(flow))
        return;

    extractor_stats.total_events++;

    auto fd = ExtractorFlowData::get<SshExtractorFlowData>(flow);

    if (!fd)
        flow->set_flow_data(fd = new SshExtractorFlowData(owner));

    auto direction = ssh_event.get_direction();
    bool c2s = PKT_FROM_CLIENT == direction;
    auto& version = ssh_event.get_version_str();
    auto packet = ssh_event.get_packet();

    if (fd->event_validation_direction or fd->event_version_direction == direction)
    {
        fd->half_reset();
        owner.dump(*fd);
        fd->reset();
    }

    if (c2s)
    {
        fd->version_c2s = std::move(version);
        trim(fd->version_c2s);
    }
    else
    {
        fd->version_s2c = std::move(version);
        trim(fd->version_s2c);
    }

    if (packet)
        fd->ts = packet->pkth->ts;
    else
        snort::packet_gettimeofday(&fd->ts);

    fd->direction = ssh_event.get_login_direction();
    fd->version = ssh_event.get_ssh_version();
    fd->event_version_direction = direction;
}

void SshExtractor::Validation::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    if (!owner.filter(flow))
        return;

    extractor_stats.total_events++;

    auto fd = ExtractorFlowData::get<SshExtractorFlowData>(flow);

    if (!fd)
        flow->set_flow_data(fd = new SshExtractorFlowData(owner));

    // log existing flow data
    if (more)
    {
        owner.logger->open_record();
        owner.log(owner.nts_fields, &event, flow);
        owner.log(owner.sip_fields, &event, flow);
        owner.log(owner.num_fields, &event, flow);
        owner.log(owner.buf_fields, &event, flow);
        owner.log(owner.fd_num_fields, (const SshExtractorFlowData*)fd);
        // owner.log(owner.fd_buf_fields, (const SshExtractorFlowData*)fd); // not yet
        owner.logger->close_record(*log_id);
    }

    const SshAlgoEvent& algo_event = *((const SshAlgoEvent*)&event);

    if (fd->event_validation_direction == 0)
    {
        fd->cipher_c2s = algo_event.get_encryption_algorithms_client_to_server();
        fd->cipher_s2c = algo_event.get_encryption_algorithms_server_to_client();
        fd->mac_c2s = algo_event.get_mac_algorithms_client_to_server();
        fd->mac_s2c = algo_event.get_mac_algorithms_server_to_client();
        fd->comp_c2s = algo_event.get_compression_algorithms_client_to_server();
        fd->comp_s2c = algo_event.get_compression_algorithms_server_to_client();
        fd->kex = algo_event.get_kex_algorithms();
        fd->host = algo_event.get_server_host_key_algorithms();

        fd->event_validation_direction = algo_event.get_direction();
        return;
    }

    // Got all events, log a complete record
    if (fd->event_validation_direction == PKT_FROM_CLIENT)
        fd->merge_with_client(algo_event);
    else
        fd->merge_with_server(algo_event);

    owner.logger->open_record();
    owner.log(owner.nts_fields, &event, flow);
    owner.log(owner.sip_fields, &event, flow);
    owner.log(owner.num_fields, &event, flow);
    // owner.log(owner.buf_fields, &event, flow); // excluded as it contains details
    owner.log(owner.fd_num_fields, (const SshExtractorFlowData*)fd);
    owner.log(owner.fd_buf_fields, (const SshExtractorFlowData*)fd);
    owner.logger->close_record(*log_id);

    fd->reset();
}

void SshExtractor::dump(const SshExtractorFlowData& fd)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    logger->open_record();

    for (const auto& f : nts_fields)
        logger->add_field(f.name, fd.ts);
    for (const auto& f : sip_fields)
        logger->add_field(f.name, "");
    for (const auto& f : num_fields)
        logger->add_field(f.name, (uint64_t)0);
    for (const auto& f : buf_fields)
        logger->add_field(f.name, "");

    log(fd_num_fields, &fd);
    log(fd_buf_fields, &fd);

    logger->close_record(*log_id);
}
