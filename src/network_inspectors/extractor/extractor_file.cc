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
// extractor_file.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_file.h"

#include "pub_sub/file_events.h"
#include "pub_sub/file_events_ids.h"

#include "extractor.h"
#include "extractor_enums.h"

using namespace snort;
using namespace std;


static uint64_t get_seen_bytes(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_seen_bytes();
}

static uint64_t get_total_bytes(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_total_bytes();
}

static uint64_t get_extracted_size(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_extracted_size();
}

static double get_duration(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_duration();
}

static bool get_timedout(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_timedout();
}

static bool get_is_orig(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_is_orig();
}

static bool get_is_extracted_cutoff(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_extracted_cutoff();
}

static const char* get_extracted_name(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_extracted_name().c_str();
}

static uint64_t get_fuid(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_fuid();
}

static const char* get_analyzer(const DataEvent*, const Flow* flow)
{
    if (flow->gadget)
        return flow->gadget->get_name();

    return "";
}

static const char* get_source(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_source().c_str();
}

static const char* get_mime_type(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_mime_type();
}

static const char* get_filename(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_filename().c_str();
}

static const char* get_sha256(const DataEvent* event, const Flow*)
{
    return ((const FileEvent*)event)->get_sha256().c_str();
}

static const map<string, ExtractorEvent::NumGetFn> sub_num_getters =
{
    {"fuid", get_fuid},
    {"seen_bytes", get_seen_bytes},
    {"total_bytes", get_total_bytes},
    {"extracted_size", get_extracted_size},
};

static const map<string, ExtractorEvent::BufGetFn> sub_buf_getters =
{
    {"analyzers", get_analyzer},
    {"source", get_source},
    {"filename", get_filename},
    {"mime_type", get_mime_type},
    {"extracted", get_extracted_name},
    {"sha256", get_sha256},
};

static const map<string, ExtractorEvent::DblGetFn> sub_dbl_getters =
{
    {"duration", get_duration},
};

static const map<string, FileExtractor::SubGetFn> sub_getters =
{
    {"timedout", get_timedout},
    {"is_orig", get_is_orig},
    {"extracted_cutoff", get_is_extracted_cutoff},
};

THREAD_LOCAL const snort::Connector::ID* FileExtractor::log_id = nullptr;

FileExtractor::FileExtractor(Extractor& i, uint32_t t, const vector<string>& fields)
    : ExtractorEvent(ServiceType::FILE, i, t)
{
    for (const auto& f : fields)
    {
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
        if (append(num_fields, sub_num_getters, f))
            continue;
        if (append(buf_fields, sub_buf_getters, f))
            continue;
        if (append(dbl_fields, sub_dbl_getters, f))
            continue;
        if (append(sub_fields, sub_getters, f))
            continue;
    }

    DataBus::subscribe_global(file_adv_pub_key, FileEventIds::FILE_COMPLETE,
        new Eof(*this, S_NAME), i.get_snort_config());
}

void FileExtractor::internal_tinit(const snort::Connector::ID* service_id)
{ log_id = service_id; }

void FileExtractor::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    if (!filter(flow))
        return;

    extractor_stats.total_events++;

    logger->open_record();
    log(nts_fields, &event, flow);
    log(sip_fields, &event, flow);
    log(num_fields, &event, flow);
    log(sub_fields, &event, flow);
    log(buf_fields, &event, flow);
    log(dbl_fields, &event, flow);
    logger->close_record(*log_id);
}

vector<const char*> FileExtractor::get_field_names() const
{
    vector<const char*> res = ExtractorEvent::get_field_names();

    for (auto& f : sub_fields)
        res.push_back(f.name);

    return res;
}
