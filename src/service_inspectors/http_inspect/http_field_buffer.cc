//---------------------------------------------------------------------------
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
//---------------------------------------------------------------------------
// http_field_buffer.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_field_buffer.h"

#include "http_common.h"
#include "http_event_reason.h"
#include "http_msg_request.h"
#include "http_msg_section.h"
#include "http_msg_status.h"
#include "http_transaction.h"
#include "http_uri.h"

using namespace HttpCommon;
using namespace HttpEnums;


static void fill_slot_from_field(HttpTmpBuffer& slot, const Field& f)
{
    int32_t len = f.length();
    if (len <= 0)
    {
        slot.field.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
        return;
    }

    slot.text.clear();
    HttpCacheData::append_escaped(slot.text, f.start(), len, len * 4);
    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void append_header_value(std::string& out, const char* label,
    HttpMsgSection* section, HeaderId id)
{
    out.append(label);
    const auto& value = section->get_classic_buffer(HTTP_BUFFER_HEADER, id, 0);

    if ( value.length() > 0 )
        HttpCacheData::append_escaped(out, value.start(), value.length(), value.length() * 4);
    else
        out.append("<no value>");
}

// For HTTP/2: strips the trailing " HTTP/1.1" suffix appended by http2_inspect.
static const uint8_t* get_raw_request_start(const Field& raw_req, int32_t& out_len,
    bool for_httpx)
{
    if (raw_req.length() <= 0)
    {
        out_len = 0;
        return nullptr;
    }

    out_len = raw_req.length();
    if (for_httpx && out_len > HX_REQUEST_LINE_SUFFIX_LEN)
        out_len -= HX_REQUEST_LINE_SUFFIX_LEN;

    return raw_req.start();
}


static void compute_decoded_uri(const HttpCacheData& cache, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section)
{
    HttpCacheData& mutable_cache = const_cast<HttpCacheData&>(cache);
    if (section)
    {
        HttpMsgRequest* req = section->get_request();
        if (req)
        {
            HttpUri* uri = req->get_http_uri();
            if (uri)
            {
                uri->fill_decoded_uri(slot.field, mutable_cache.decoded_path);
                return;
            }
        }
    }

    slot.field.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
    mutable_cache.decoded_path.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
}

static void compute_method_str(const HttpCacheData&, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section)
{
    fill_slot_from_field(slot, section->get_classic_buffer(HTTP_BUFFER_METHOD, 0, 0));
}

static void compute_request_size(const HttpCacheData& cache, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section) // cppcheck-suppress constParameterCallback
{
    if (section)
    {
        const HttpTransaction* txn = section->get_transaction();
        const uint64_t val = txn->get_message_length(txn->get_request(), HttpCommon::SRC_CLIENT);
        slot.num = val > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(val);
    }
    else
        slot.num = cache.request.request_size;

    slot.field.set(sizeof(uint32_t), reinterpret_cast<const uint8_t*>(&slot.num));
}

static void compute_request_line_length(const HttpCacheData& cache, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section)
{
    if (section)
    {
        HttpMsgRequest* req = section->get_transaction()->get_request();
        if (req == nullptr)
        {
            slot.field.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
            return;
        }
        slot.num = static_cast<uint32_t>(req->get_length());
    }
    else
        slot.num = cache.request.request_line_length;

    slot.field.set(sizeof(uint32_t), reinterpret_cast<const uint8_t*>(&slot.num));
}

static void compute_response_size(const HttpCacheData&, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section) // cppcheck-suppress constParameterCallback
{
    const HttpTransaction* txn = section->get_transaction();
    const uint64_t val = txn->get_message_length(txn->get_status(), HttpCommon::SRC_SERVER);

    slot.num = val > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(val);
    slot.field.set(sizeof(uint32_t), reinterpret_cast<const uint8_t*>(&slot.num));
}

static void compute_version_str(const HttpCacheData&, HttpTmpBuffer& slot,
    const HttpBufferInfo& buf, HttpMsgSection* section) // cppcheck-suppress constParameterCallback
{
    VersionId version = section->get_version_id(buf);
    const auto& iter = VersionEnumToStr.find(version);
    if (iter == VersionEnumToStr.end())
    {
        slot.field.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
        return;
    }

    slot.text = "HTTP/";
    slot.text.append(iter->second);
    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_user_agent_str(const HttpCacheData&, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section)
{
    fill_slot_from_field(slot, section->get_classic_buffer(HTTP_BUFFER_HEADER, HEAD_USER_AGENT, 0));
}

static void compute_referer_str(const HttpCacheData&, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section)
{
    fill_slot_from_field(slot, section->get_classic_buffer(HTTP_BUFFER_HEADER, HEAD_REFERER, 0));
}

static void compute_detail_119_20(const HttpCacheData&, HttpTmpBuffer& slot,
    const HttpBufferInfo& buf, HttpMsgSection* section) // cppcheck-suppress constParameterCallback
{
    // EVENT_MAX_HEADERS
    // Header Count: XXX
    slot.text = "Header Count: ";
    auto cnt = section->get_num_headers(buf);
    if (cnt >= 0)
        slot.text.append(std::to_string(cnt));
    else
    {
        slot.text.append("<no header ");
        slot.text.append(std::to_string(cnt));
        slot.text.append(">");
    }

    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_287(const HttpCacheData&, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section)
{
    // EVENT_DISALLOWED_METHOD
    // HTTP Method: XXX
    slot.text = "HTTP Method: ";
    const Field& method = section->get_classic_buffer(HTTP_BUFFER_METHOD, 0, 0);
    if (method.length() > 0)
        slot.text.append(reinterpret_cast<const char*>(method.start()), method.length());
    else
    {
        slot.text.append("<no method ");
        slot.text.append(std::to_string(method.length()));
        slot.text.append(">");
    }

    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_298(const HttpCacheData& cache, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection*)
{
    // EVENT_EVENT_REQUEST_SIZE_TOO_LONG
    // Request Size: XXX
    slot.text = "Request Size: " + std::to_string(cache.request.request_size);
    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_299(const HttpCacheData& cache, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section)
{
    // EVENT_REQUEST_LINE_LENGTH_TOO_LONG
    // Request Line Length: XXX
    slot.text = "Request Line Length: " +
        std::to_string(cache.request.request_line_length) + ", Request Line: ";

    if (section)
    {
        const Field& raw_req = section->get_classic_buffer(HTTP_BUFFER_RAW_REQUEST, 0, 0);
        int32_t raw_len = 0;
        const uint8_t* raw = get_raw_request_start(raw_req, raw_len,
            section->get_session_data()->is_for_httpx());
        if (raw && raw_len > 0)
        {
            HttpCacheData::append_escaped(slot.text, raw, raw_len, MAX_REQUEST_LINE_LOG_LEN);
            slot.field.set(static_cast<int32_t>(slot.text.length()),
                reinterpret_cast<const uint8_t*>(slot.text.c_str()));
            return;
        }
    }

    if (cache.request.request_line_raw_len > 0)
        HttpCacheData::append_escaped(slot.text,
            cache.request.request_line_raw.data(),
            cache.request.request_line_raw_len, MAX_REQUEST_LINE_LOG_LEN);
    else
        slot.text.append("<no request>");

    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_300(const HttpCacheData& cache, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section)
{
    // EVENT_REQUEST_LINE_NOT_VALID
    // XXX, Request Line: YYY
    slot.text = get_http_event_reason_msg(cache.request.reason_code_detail_300);
    slot.text.append(", Request Line: ");

    if (section)
    {
        const Field& raw_req = section->get_classic_buffer(HTTP_BUFFER_RAW_REQUEST, 0, 0);
        int32_t raw_len = 0;
        const uint8_t* raw = get_raw_request_start(raw_req, raw_len,
            section->get_session_data()->is_for_httpx());
        if (raw and raw_len > 0)
        {
            HttpCacheData::append_escaped(slot.text, raw, raw_len, MAX_REQUEST_LINE_LOG_LEN);
            slot.field.set(static_cast<int32_t>(slot.text.length()),
                reinterpret_cast<const uint8_t*>(slot.text.c_str()));
            return;
        }
    }

    if (cache.request.request_line_raw_len > 0)
        HttpCacheData::append_escaped(slot.text,
            cache.request.request_line_raw.data(),
            cache.request.request_line_raw_len, MAX_REQUEST_LINE_LOG_LEN);
    else
        slot.text.append("<no request>");

    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_301(const HttpCacheData& cache, HttpTmpBuffer& slot,
    const HttpBufferInfo&, HttpMsgSection* section)
{
    // EVENT_HEADER_INVALID_CL_OR_TE
    // <reason>[, Content-Length: XXX][, Transfer-Encoding: YYY]
    const auto code = cache.reason_code_detail_301[section->get_source_id()];

    slot.text = get_detail_301_reason(code);

    switch ( code )
    {
    case DETAIL_301_NONE:
        break;
    case DETAIL_301_CL_AND_TE_PRESENT:
        append_header_value(slot.text, ", Content-Length: ", section, HEAD_CONTENT_LENGTH);
        append_header_value(slot.text, ", Transfer-Encoding: ", section, HEAD_TRANSFER_ENCODING);
        break;
    case DETAIL_301_NEGATIVE_CL:
        append_header_value(slot.text, ", Content-Length: ", section, HEAD_CONTENT_LENGTH);
        break;
    case DETAIL_301_HTTPX_HAS_TE:
        append_header_value(slot.text, ", Transfer-Encoding: ", section, HEAD_TRANSFER_ENCODING);
        break;
    }

    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

// ---------------------------------------------------------------------------
// Descriptor table and shared materializer
// ---------------------------------------------------------------------------

using TmpComputeFn = void(*)(const HttpCacheData&, HttpTmpBuffer&,
    const HttpBufferInfo&, HttpMsgSection*);

struct TmpBufferDescriptor
{
    TmpComputeFn compute;
    bool requires_section;
};

static const TmpBufferDescriptor tmp_buffer_desc[HTTP_TMP_BUFFER_CNT] =
{
    { compute_decoded_uri,          true  }, // HTTP_BUFFER_DECODED_URI
    { compute_method_str,           true  }, // HTTP_BUFFER_METHOD_STR
    { compute_request_size,         false }, // HTTP_BUFFER_REQUEST_SIZE
    { compute_request_line_length,  false }, // HTTP_BUFFER_REQUEST_LINE_LENGTH
    { compute_response_size,        true  }, // HTTP_BUFFER_RESPONSE_SIZE
    { compute_version_str,          true  }, // HTTP_BUFFER_VERSION_STR
    { compute_user_agent_str,       true  }, // HTTP_BUFFER_USER_AGENT_STR
    { compute_referer_str,          true  }, // HTTP_BUFFER_REFERER_STR
    { compute_detail_119_20,        true  }, // DETAIL_119_20
    { compute_detail_119_287,       true  }, // DETAIL_119_287
    { compute_detail_119_298,       false }, // DETAIL_119_298
    { compute_detail_119_299,       false }, // DETAIL_119_299
    { compute_detail_119_300,       false }, // DETAIL_119_300
    { compute_detail_119_301,       true  }, // DETAIL_119_301
};

const Field& get_http_tmp_buffer(HttpCacheData& cache, const HttpBufferInfo& buf,
    HttpMsgSection* section)
{
    const unsigned index = buf.type - HTTP_FIRST_TMP_BUFFER;
    assert(index < HTTP_TMP_BUFFER_CNT);
    const TmpBufferDescriptor& desc = tmp_buffer_desc[index];

    if (!section && desc.requires_section)
        return Field::FIELD_NULL;

    HttpTmpBuffer& slot = cache.tmp_bufs[index];
    if (slot.field.length() == STAT_NOT_COMPUTE)
        desc.compute(cache, slot, buf, section);

    return slot.field;
}

const Field& HttpTmpFieldBuffer::get_buffer_data(unsigned int type)
{
    return get_http_tmp_buffer(get_cache_data(), HttpBufferInfo(type), nullptr);
}

