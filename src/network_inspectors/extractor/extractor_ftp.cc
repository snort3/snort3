//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// extractor_ftp.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_ftp.h"

#include <sys/time.h>

#include "detection/detection_engine.h"
#include "flow/flow_key.h"
#include "profiler/profiler.h"
#include "pub_sub/ftp_events.h"
#include "service_inspectors/ftp_telnet/ftpp_si.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"
#include "utils/util_net.h"

#include "extractor.h"
#include "extractor_enums.h"
#include "extractor_flow_data.h"

#define FILE_STATUS_OK "150"

using namespace snort;
using namespace std;

namespace req
{
static pair<const char*, uint16_t> get_cmd(const DataEvent* event, const Packet*, const Flow*)
{
    const auto& req = ((const FtpRequestEvent*)event)->get_request();
    return {req.cmd_begin, req.cmd_size};
}

static pair<const char*, uint16_t> get_arg(const DataEvent* event, const Packet*, const Flow*)
{
    const auto& req = ((const FtpRequestEvent*)event)->get_request();
    return {req.param_begin, req.param_size};
}

static pair<const char*, uint16_t> get_user(const DataEvent* event, const Packet*, const Flow*)
{
    const auto& req = ((const FtpRequestEvent*)event)->get_request();
    const auto cmd = string(req.cmd_begin, req.cmd_size);
    if (cmd == "USER")
        return {req.param_begin, req.param_size};

    return {};
}

static const map<string, ExtractorEvent::StrGetFn> sub_str_getters =
{
    {"command", get_cmd},
    {"arg", get_arg},
    {"user", get_user},
};
}

FtpRequestExtractor::FtpRequestExtractor(Extractor& i, ExtractorLogger& l,
    uint32_t t, const vector<string>& fields) : ExtractorEvent(i, l, t)
{
    for (const auto& f : fields)
    {
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
        if (append(str_fields, req::sub_str_getters, f))
            continue;
    }

    DataBus::subscribe(ftp_pub_key, FtpEventIds::FTP_REQUEST, new Req(*this, S_NAME));
}

void FtpRequestExtractor::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    uint32_t tid = 0;

#ifndef DISABLE_TENANT_ID
    tid = flow->key->tenant_id;
#endif

    if (tenant_id != tid)
        return;

    extractor_stats.total_event++;

    Packet* packet = DetectionEngine::get_current_packet();

    logger.open_record();
    log(nts_fields, &event, packet, flow);
    log(sip_fields, &event, packet, flow);
    log(num_fields, &event, packet, flow);
    log(str_fields, &event, packet, flow, logger.is_strict());
    logger.close_record();
}

static uint64_t parse_last_num(const char *str, uint16_t size)
{
    constexpr uint8_t max_digits = 20;
    char num_str[max_digits + 1] = {};
    uint8_t pos = max_digits;

    for (size_t i = size; i > 0; --i)
    {
        char c = str[i - 1];
        if (isdigit(c))
        {
            num_str[--pos] = c;
        }
        else if (pos < max_digits)
            break;
    }

    return (pos < max_digits) ? stoull(&num_str[pos]) : 0;
}

namespace resp
{
static pair<const char*, uint16_t> get_code(const DataEvent* event, const Packet*, const Flow*)
{
    const auto& response = ((const FtpResponseEvent*)event)->get_response();
    return {response.rsp_begin, response.rsp_size};
}

static pair<const char*, uint16_t> get_msg(const DataEvent* event, const Packet*, const Flow*)
{
    const auto& response = ((const FtpResponseEvent*)event)->get_response();
    return {response.msg_begin, response.msg_size};
}

static const SfIp& get_orig_ip(const DataEvent* event, const Packet*, const Flow*)
{
    if (((const FtpResponseEvent*)event)->is_passive())
        return ((const FtpResponseEvent*)event)->get_client_ip();
    else
        return ((const FtpResponseEvent*)event)->get_server_ip();
}

static const SfIp& get_resp_ip(const DataEvent* event, const Packet*, const Flow*)
{
    if (((const FtpResponseEvent*)event)->is_passive())
        return ((const FtpResponseEvent*)event)->get_server_ip();
    else
        return ((const FtpResponseEvent*)event)->get_client_ip();
}

static uint64_t get_resp_port(const DataEvent* event, const Packet*, const Flow*)
{
    if (((const FtpResponseEvent*)event)->is_passive())
        return (uint64_t)((const FtpResponseEvent*)event)->get_server_port();
    else
        return (uint64_t)((const FtpResponseEvent*)event)->get_client_port();
}

static uint64_t get_file_size(const DataEvent* event, const Packet*, const Flow*)
{
    const auto& resp = ((const FtpResponseEvent*)event)->get_response();
    const auto& code = string(resp.rsp_begin, resp.rsp_size);

    if (code == FILE_STATUS_OK)
        return parse_last_num(resp.msg_begin, resp.msg_size);

    return 0;
}

static int8_t get_mode(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const FtpResponseEvent*)event)->get_mode();
}

static const map<string, ExtractorEvent::StrGetFn> sub_str_getters =
{
    {"reply_code", get_code},
    {"reply_msg", get_msg},
};

static const map<string, ExtractorEvent::NumGetFn> sub_num_getters =
{
    {"file_size", get_file_size},
    {"data_channel.resp_p", get_resp_port}
};

static const map<string, ExtractorEvent::SipGetFn> sub_sip_getters =
{
    {"data_channel.orig_h", get_orig_ip},
    {"data_channel.resp_h", get_resp_ip}
};

static const map<string, FtpResponseExtractor::SubGetFn> sub_getters =
{
    {"data_channel.passive", get_mode},
};
}

FtpResponseExtractor::FtpResponseExtractor(Extractor& i, ExtractorLogger& l,
    uint32_t t, const vector<string>& fields) : ExtractorEvent(i, l, t)
{
    for (const auto& f : fields)
    {
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(sip_fields, resp::sub_sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
        if (append(num_fields, resp::sub_num_getters, f))
            continue;
        if (append(str_fields, resp::sub_str_getters, f))
            continue;
        if (append(sub_fields, resp::sub_getters, f))
            continue;
    }

    DataBus::subscribe(ftp_pub_key, FtpEventIds::FTP_RESPONSE, new Resp(*this, S_NAME));
}

template<>
void ExtractorEvent::log<vector<FtpResponseExtractor::SubField>, DataEvent*, Packet*, Flow*, bool>(
    const vector<FtpResponseExtractor::SubField>& fields, DataEvent* event, Packet* pkt, Flow* flow, bool strict)
{
    for (const auto& f : fields)
    {
        const auto mode = f.get(event, pkt, flow);
        if (mode != FTPP_XFER_NOT_SET)
            mode == FTPP_XFER_PASSIVE ? logger.add_field(f.name, true) : logger.add_field(f.name, false);
        else if (strict)
            logger.add_field(f.name, "");
    }
}

void FtpResponseExtractor::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    uint32_t tid = 0;

#ifndef DISABLE_TENANT_ID
    tid = flow->key->tenant_id;
#endif

    if (tenant_id != tid)
        return;

    extractor_stats.total_event++;

    Packet* packet = DetectionEngine::get_current_packet();

    logger.open_record();
    log(nts_fields, &event, packet, flow);
    log(sip_fields, &event, packet, flow);
    log(num_fields, &event, packet, flow);
    log(str_fields, &event, packet, flow, logger.is_strict());
    log(sub_fields, &event, packet, flow, logger.is_strict());
    logger.close_record();
}

vector<const char*> FtpResponseExtractor::get_field_names() const
{
    vector<const char*> res = ExtractorEvent::get_field_names();

    for (auto& f : sub_fields)
        res.push_back(f.name);

    return res;
}

class FtpExtractorFlowData : public ExtractorFlowData
{
public:
    static constexpr ServiceType type_id = ServiceType::FTP;

    FtpExtractorFlowData(FtpExtractor& owner)
        : ExtractorFlowData(type_id, owner.get_inspector()), owner(owner) {}

    ~FtpExtractorFlowData() override
    {
        if (has_data)
            owner.dump(*this);
    }

    void reset();

    string cmd;
    string arg;
    string usr;
    string code;
    string msg;
    uint64_t file_size = 0;

    int8_t mode = FTPP_XFER_NOT_SET;
    SfIp orig_h = {};
    SfIp resp_h = {};
    uint64_t resp_p = 0;

    struct timeval ts = {};
    bool has_data = false;

private:
    FtpExtractor& owner;
};

namespace flow
{
static const char* get_cmd(const FtpExtractorFlowData& fd)
{
    return fd.cmd.c_str();
}

static const char* get_arg(const FtpExtractorFlowData& fd)
{
    return fd.arg.c_str();
}

static const char* get_user(const FtpExtractorFlowData& fd)
{
    return fd.usr.c_str();
}

static const char* get_code(const FtpExtractorFlowData& fd)
{
    return fd.code.c_str();
}

static const char* get_msg(const FtpExtractorFlowData& fd)
{
    return fd.msg.c_str();
}

static const SfIp& get_orig_ip(const FtpExtractorFlowData& fd)
{
    return fd.orig_h;
}

static const SfIp& get_resp_ip(const FtpExtractorFlowData& fd)
{
    return fd.resp_h;
}

static uint64_t get_file_size(const FtpExtractorFlowData& fd)
{
    return fd.file_size;
}

static uint64_t get_resp_port(const FtpExtractorFlowData& fd)
{
    return fd.resp_p;
}

static int8_t get_mode(const FtpExtractorFlowData& fd)
{
    return fd.mode;
}

static const map<string, FtpExtractor::FdBufGetFn> fd_buf_getters =
{
    {"command", get_cmd},
    {"arg", get_arg},
    {"user", get_user},
    {"reply_code", get_code},
    {"reply_msg", get_msg}
};

static const map<string, FtpExtractor::FdSipGetFn> fd_sip_getters =
{
    {"data_channel.orig_h", get_orig_ip},
    {"data_channel.resp_h", get_resp_ip}
};

static const map<string, FtpExtractor::FdNumGetFn> fd_num_getters =
{
    {"file_size", get_file_size},
    {"data_channel.resp_p", get_resp_port}
};

static const map<string, FtpExtractor::FdSubGetFn> fd_sub_getters =
{
    {"data_channel.passive", get_mode},
};
}

FtpExtractor::FtpExtractor(Extractor& i, ExtractorLogger& l,
    uint32_t t, const vector<string>& fields) : ExtractorEvent(i, l, t)
{
    for (const auto& f : fields)
    {
        if (append(fd_buf_fields, flow::fd_buf_getters, f))
            continue;
        if (append(fd_sip_fields, flow::fd_sip_getters, f))
            continue;
        if (append(fd_num_fields, flow::fd_num_getters, f))
            continue;
        if (append(fd_sub_fields, flow::fd_sub_getters, f))
            continue;
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
    }

    DataBus::subscribe(ftp_pub_key, FtpEventIds::FTP_REQUEST, new Req(*this, S_NAME));
    DataBus::subscribe(ftp_pub_key, FtpEventIds::FTP_RESPONSE, new Resp(*this, S_NAME));
}

vector<const char*> FtpExtractor::get_field_names() const
{
    vector<const char*> res = ExtractorEvent::get_field_names();

    for (auto& f : fd_buf_fields)
        res.push_back(f.name);
    for (auto& f : fd_sip_fields)
        res.push_back(f.name);
    for (auto& f : fd_num_fields)
        res.push_back(f.name);
    for (auto& f : fd_sub_fields)
        res.push_back(f.name);

    return res;
}

void FtpExtractorFlowData::reset()
{
    cmd.clear();
    arg.clear();
    code.clear();
    msg.clear();
    file_size = 0;

    mode = FTPP_XFER_NOT_SET;
    orig_h.clear();
    resp_h.clear();
    resp_p = 0;

    ts = {};
    has_data = false;
}

template<>
// Passing FtpExtractorFlowData as a pointer.
// Unfortunately, template expansion is confused if we pass an object (a reference).
void ExtractorEvent::log<vector<FtpExtractor::FdBufField>, const FtpExtractorFlowData*>(
    const vector<FtpExtractor::FdBufField>& fields, const FtpExtractorFlowData* fd)
{
    for (const auto& f : fields)
    {
        auto d = f.get(*fd);
        logger.add_field(f.name, d);
    }
}

template<>
void ExtractorEvent::log<vector<FtpExtractor::FdSipField>, const FtpExtractorFlowData*>(
    const vector<FtpExtractor::FdSipField>& fields, const FtpExtractorFlowData* fd)
{
    for (const auto& f : fields)
    {
        auto d = f.get(*fd);
        logger.add_field(f.name, d);
    }
}

template<>
void ExtractorEvent::log<vector<FtpExtractor::FdNumField>, const FtpExtractorFlowData*>(
    const vector<FtpExtractor::FdNumField>& fields, const FtpExtractorFlowData* fd)
{
    for (const auto& f : fields)
    {
        auto d = f.get(*fd);
        logger.add_field(f.name, d);
    }
}

template<>
void ExtractorEvent::log<vector<FtpExtractor::FdSubField>, const FtpExtractorFlowData*, bool>(
    const vector<FtpExtractor::FdSubField>& fields, const FtpExtractorFlowData* fd, bool strict)
{
    for (const auto& f : fields)
    {
        const auto mode = f.get(*fd);
        if (mode != FTPP_XFER_NOT_SET)
            mode == FTPP_XFER_PASSIVE ? logger.add_field(f.name, true) : logger.add_field(f.name, false);
        else if (strict)
            logger.add_field(f.name, "");
    }
}

static const string commands_to_log = "RETR, STOR, PASV, PORT, DELE, APPE, EPRT, EPSV, STOU, ACCT";

void FtpExtractor::Req::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    uint32_t tid = 0;

#ifndef DISABLE_TENANT_ID
    tid = flow->key->tenant_id;
#endif

    if (owner.tenant_id != tid)
        return;

    extractor_stats.total_event++;

    Packet* p = DetectionEngine::get_current_packet();
    auto fd = ExtractorFlowData::get<FtpExtractorFlowData>(flow);

    if (!fd)
        flow->set_flow_data(fd = new FtpExtractorFlowData(owner));
    else if (!fd->cmd.empty())
    {
        // log existing flow data
        owner.logger.open_record();
        owner.log(owner.nts_fields, &event, p, flow);
        owner.log(owner.sip_fields, &event, p, flow);
        owner.log(owner.num_fields, &event, p, flow);
        owner.log(owner.fd_buf_fields, (const FtpExtractorFlowData*)fd);
        owner.log(owner.fd_sip_fields, (const FtpExtractorFlowData*)fd);
        owner.log(owner.fd_num_fields, (const FtpExtractorFlowData*)fd);
        owner.log(owner.fd_sub_fields, (const FtpExtractorFlowData*)fd, owner.logger.is_strict());
        owner.logger.close_record();

        fd->reset();
    }

    const auto& req = ((FtpRequestEvent*)&event)->get_request();
    const auto cmd = string(req.cmd_begin, req.cmd_size);

    if (cmd == "USER")
    {
        fd->usr = string(req.param_begin, req.param_size);
        return;
    }

    if (string::npos == commands_to_log.find(cmd))
        // no need to save it
        return;

    fd->cmd = cmd;
    fd->arg = string(req.param_begin, req.param_size);

    fd->ts = p->pkth->ts;
    fd->has_data = true;
}

void FtpExtractor::Resp::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    uint32_t tid = 0;

#ifndef DISABLE_TENANT_ID
    tid = flow->key->tenant_id;
#endif

    if (owner.tenant_id != tid)
        return;

    extractor_stats.total_event++;

    auto fd = ExtractorFlowData::get<FtpExtractorFlowData>(flow);

    if (!fd or fd->cmd.empty())
        // no need to save this response
        return;

    const auto ftp_event = (FtpResponseEvent*)&event;
    const auto& resp = ftp_event->get_response();
    const auto code = string(resp.rsp_begin, resp.rsp_size);
    const auto msg = string(resp.msg_begin, resp.msg_size);

    fd->code = code;
    fd->msg = msg;

    if (code == FILE_STATUS_OK)
        fd->file_size = parse_last_num(resp.msg_begin, resp.msg_size);

    if (FTPP_XFER_NOT_SET == ftp_event->get_mode())
        return;

    if (ftp_event->is_passive())
    {
        fd->mode = FTPP_XFER_PASSIVE;
        fd->orig_h = ftp_event->get_client_ip();
        fd->resp_h = ftp_event->get_server_ip();
        fd->resp_p = ftp_event->get_server_port();
    }
    else
    {
        fd->mode = FTPP_XFER_ACTIVE;
        fd->orig_h = ftp_event->get_server_ip();
        fd->resp_h = ftp_event->get_client_ip();
        fd->resp_p = ftp_event->get_client_port();
    }
}

void FtpExtractor::dump(const FtpExtractorFlowData& fd)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    logger.open_record();

    for (const auto& f : nts_fields)
        logger.add_field(f.name, fd.ts);
    for (const auto& f : sip_fields)
        logger.add_field(f.name, "");
    for (const auto& f : num_fields)
        logger.add_field(f.name, (uint64_t)0);

    log(fd_buf_fields, &fd);
    log(fd_sip_fields, &fd);
    log(fd_num_fields, &fd);
    log(fd_sub_fields, &fd, logger.is_strict());

    logger.close_record();
}


#ifdef UNIT_TEST

#include "catch/snort_catch.h"

TEST_CASE("Parse file size", "[extractor]")
{
    const char* resp_msg1 = "Here comes the directory listing (total size 04096 bytes).";
    const char* resp_msg2 = "Opening data connection for log10.txt, size 0 bytes";
    const char* resp_msg3 = "Opening BINARY mode data connection for \"files-1.3-1.txt\" (218850 bytes).";

    CHECK(4096 == parse_last_num(resp_msg1 ,58));
    CHECK(0 == parse_last_num(resp_msg2, 52));
    CHECK(218850 == parse_last_num(resp_msg3, 73));
}

#endif
