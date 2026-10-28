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

#include <algorithm>
#include <cstring>
#include <memory>

#include "http_cache_data.h"
#include "http_common.h"
#include "http_context_data.h"
#include "http_msg_request.h"
#include "http_msg_section.h"
#include "http_msg_status.h"
#include "http_transaction.h"
#include "http_uri.h"

using namespace HttpCommon;
using namespace HttpEnums;

void append_escaped(std::string& out, const uint8_t* data, int32_t len, int32_t max_append)
{
    static constexpr char hex_chars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    const int32_t limit = static_cast<int32_t>(out.length()) + max_append;
    for (int32_t i = 0; i < len; ++i)
    {
        const int32_t remaining = limit - static_cast<int32_t>(out.length());
        if (remaining <= 0)
            break;
        const uint8_t c = data[i];
        if (c == '\\')
        {
            if (remaining < 4)
                break;
            out.append("\\x5c");
        }
        else if (c < 0x20 || c > 0x7E)
        {
            if (remaining < 4)
                break;
            out.append("\\x");
            out.push_back(hex_chars[(c >> 4) & 0x0F]);
            out.push_back(hex_chars[c & 0x0F]);
        }
        else
            out.push_back(static_cast<char>(c));
    }
}

static constexpr char REDACTED[] = "<redacted>";

// A name carrying non-token bytes cannot be matched against the list below, so the value it
// introduces is never trusted.
static bool is_token_name(const uint8_t* name, int32_t len)
{
    for (int32_t k = 0; k < len; ++k)
    {
        if (!token_char[name[k]])
            return false;
    }
    return true;
}

// Non-token bytes are dropped so a mangled name cannot evade the match.
static bool is_credential_header(const uint8_t* name, int32_t len)
{
    static const char* const credential_names[] = {
        "authorization", "cookie", "proxy-authorization", "set-cookie",
        "x-api-key", "x-auth-token"
    };
    static constexpr int32_t longest_name = 19;

    if (len <= 0)
        return false;

    std::string lower;
    for (int32_t k = 0; k < len; ++k)
    {
        const uint8_t c = name[k];
        if (!token_char[c])
            continue;
        lower.push_back(static_cast<char>(((c >= 'A') and (c <= 'Z')) ? c + ('a' - 'A') : c));
        if (static_cast<int32_t>(lower.length()) > longest_name)
            return false;
    }

    for (const char* candidate : credential_names)
    {
        if (lower == candidate)
            return true;
    }
    return false;
}

void append_header_detail(std::string& out, const uint8_t* data, int32_t len, int32_t max_append)
{
    int32_t name_len = 0;
    while (name_len < len and data[name_len] != ':')
        ++name_len;

    // A line keeps CR/LF only when obs-fold spliced continuations into it, so the
    // bytes past the first colon may hold further name/value pairs.
    int32_t fold_pos = 0;
    while (fold_pos < len and !is_cr_lf[data[fold_pos]])
        ++fold_pos;

    if (name_len == len or fold_pos < name_len)
    {
        out.append(REDACTED);
        return;
    }

    if (fold_pos == len and is_token_name(data, name_len) and
        !is_credential_header(data, name_len))
    {
        append_escaped(out, data, len, max_append);
        return;
    }

    int32_t prefix_len = name_len + 1;
    while (prefix_len < len and is_sp_tab[data[prefix_len]])
        ++prefix_len;

    const int32_t prefix_budget = max_append - static_cast<int32_t>(sizeof(REDACTED)) + 1;
    append_escaped(out, data, prefix_len, std::max(prefix_budget, 0));
    out.append(REDACTED);
}

void append_content_type_detail(std::string& out, const uint8_t* value, int32_t len,
    int32_t max_len)
{
    // Bytes past an obs-fold belong to another header and may be a credential, so cut them off
    int32_t end = 0;
    while (end < len and !is_cr_lf[value[end]])
        end++;
    const int32_t redacted_len = (end < len) ? static_cast<int32_t>(sizeof(REDACTED)) - 1 : 0;

    int32_t start = 0;
    while (start < end and is_sp_tab[value[start]])
        start++;
    while (end > start and is_sp_tab[value[end-1]])
        end--;

    if (start == end)
        out.append("<no value>");
    else
    {
        const int32_t budget = max_len - static_cast<int32_t>(out.length()) - redacted_len;
        append_escaped(out, value + start, end - start, std::max(budget, 0));
    }
    out.append(REDACTED, redacted_len);
}

static const char* get_http_event_reason_msg(RequestLineInvalidReasonCode event)
{
    switch (event)
    {
    case BAD_REQUEST_TERMINATION:
        return "HTTP request bad termination";
    case BAD_VERSION:
        return "HTTP version is bad";
    case IMPROPER_WS:
        return "Improper whitespace in start line";
    case INVALID_SUBVERSION:
        return "Invalid subversion";
    case METHOD_NOT_PRESENT:
        return "HTTP method missing";
    case METHOD_NOT_UPPERCASE:
        return "HTTP method not all upper case";
    case NON_RFC_CHAR:
        return "Non-RFC character present";
    case SIMPLE_REQUEST:
        return "Simple request (no version)";
    case UNESCAPED_SPACE_URI:
        return "Unescaped space in URI";
    case UNKNOWN_METHOD:
        return "Unknown method";
    case URI_MISSING:
        return "URI missing";
    case VERSION_HIGHER_THAN_1:
        return "Version higher than 1";
    case VERSION_MALFORMED:
        return "HTTP version is malformed";
    case VERSION_NOT_UPPERCASE:
        return "HTTP version not all upper case";
    case NONE:
        return "Unknown reason";
    }

    assert(false);
    return "Unknown reason";
}

static const char* get_detail_301_reason(Detail301ReasonCode code)
{
    switch (code)
    {
    case DETAIL_301_NONE:
        return "No detail available";
    case DETAIL_301_CL_AND_TE_PRESENT:
        return "Content-Length and Transfer-Encoding are both present";
    case DETAIL_301_HTTPX_HAS_TE:
        return "HTTP/2 or HTTP/3 has Transfer-Encoding";
    case DETAIL_301_NEGATIVE_CL:
        return "Content-Length has a negative value";
    }

    assert(false);
    return "Unknown reason";
}

static void append_header_value(std::string& out, const char* label,
    HttpMsgSection* section, HeaderId id)
{
    out.append(label);

    assert(section);
    const auto& value = section->get_classic_buffer(HTTP_BUFFER_HEADER, id, 0);

    if ( value.length() > 0 )
        append_escaped(out, value.start(), value.length(), value.length() * 4);
    else
        out.append("<no value>");
}

// HTTP/x rebuilt request lines carry a synthetic HTTP/1.1 suffix; log the real version.
static bool append_rebuilt_raw_request_line(std::string& out, HttpMsgSection* section,
    int32_t max_append)
{
    assert(section);
    const Field& raw_req = section->get_classic_buffer(HTTP_BUFFER_RAW_REQUEST, 0, 0);
    if (raw_req.length() <= 0)
        return false;

    int32_t raw_len = raw_req.length();

    std::string version_suffix;
    if (section->get_session_data()->is_for_httpx())
    {
        if (raw_len > HX_REQUEST_LINE_SUFFIX_LEN)
            raw_len -= HX_REQUEST_LINE_SUFFIX_LEN;

        assert(section->get_request());
        const char* const version_str = version_id_to_str(section->get_request()->get_version_id());
        version_suffix = " HTTP/";
        version_suffix.append(version_str ? version_str : "?");
    }

    const int32_t escape_budget = max_append - static_cast<int32_t>(version_suffix.length());
    append_escaped(out, raw_req.start(), raw_len,
        std::max(escape_budget, 0));
    out.append(version_suffix);

    return true;
}

struct WireSnapshotView
{
    const HttpSplitterSnapshot* snap_300 = nullptr;
    const HttpSplitterSnapshot* snap_299 = nullptr;
    const HttpSplitterSnapshot* snap_298 = nullptr;

    bool has_any() const { return snap_300 or snap_299 or snap_298; }

    const HttpSplitterSnapshot* best() const
    { return snap_298 ? snap_298 : (snap_299 ? snap_299 : snap_300); }

    const HttpSplitterSnapshot* for_299() const { return snap_299; }
    const HttpSplitterSnapshot* for_300() const { return snap_300; }
};

struct HttpBufferSource
{
    struct Bytes
    {
        const uint8_t* data = nullptr;
        unsigned len = 0;
        bool present = false;
    };

    HttpMsgSection* section = nullptr;
    WireSnapshotView wire;

    bool has_section() const { return section != nullptr; }
    bool has_any_snapshot() const { return wire.has_any(); }

    // Use the scan-time size for this request when 298 was deferred to eval.
    uint32_t request_size() const
    {
        if (const HttpSplitterSnapshot* s = wire.best())
            return s->request_size;

        assert(has_section());

        const HttpTransaction* const txn = section->get_transaction();
        if (txn->has_pending_size_298())
            return txn->get_pending_size_298();

        const uint64_t val = txn->get_message_length(txn->get_request(), HttpCommon::SRC_CLIENT);
        return val > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(val);
    }

    bool request_line_length(uint32_t& out) const
    {
        if (const HttpSplitterSnapshot* s = wire.best())
        {
            out = s->request_line_length;
            return true;
        }

        assert(has_section());

        const HttpTransaction* const txn = section->get_transaction();
        if (txn->has_pending_length_299())
        {
            out = txn->get_pending_length_299();
            return true;
        }

        const HttpMsgRequest* req = txn->get_request();
        if (req == nullptr)
            return false;
        out = static_cast<uint32_t>(req->get_length());
        return true;
    }

    bool request_line_length_detail(uint32_t& out) const
    {
        if (const HttpSplitterSnapshot* s = wire.for_299())
        {
            out = s->request_line_length;
            return true;
        }

        if (!has_section())
            return false;

        if (section->get_transaction()->has_pending_length_299())
        {
            out = section->get_transaction()->get_pending_length_299();
            return true;
        }

        if (section->get_session_data()->is_for_httpx())
        {
            const Field& raw_req = section->get_classic_buffer(HTTP_BUFFER_RAW_REQUEST, 0, 0);
            if (raw_req.length() <= HX_REQUEST_LINE_SUFFIX_LEN + 1)
                return false;
            out = static_cast<uint32_t>(raw_req.length()) - HX_REQUEST_LINE_SUFFIX_LEN - 1;
            return true;
        }

        const HttpMsgRequest* req = section->get_transaction()->get_request();
        if (req == nullptr)
            return false;
        out = static_cast<uint32_t>(req->get_start_line_length());
        return true;
    }

    RequestLineInvalidReasonCode request_line_invalid_reason() const
    {
        if (const HttpSplitterSnapshot* s = wire.for_300())
            return s->reason_code_detail_300;

        if (!has_section())
            return NONE;

        const HttpMsgRequest* req = section->get_request();
        return req ? req->get_request_line_invalid_reason() : NONE;
    }

    void append_raw_request_line(std::string& out, const HttpSplitterSnapshot* snap) const
    {
        if (snap)
        {
            if (snap->raw_request_line_len == 0)
            {
                out.append("<no request>");
                return;
            }

            const uint8_t* const raw = snap->raw_request_line.data();
            int32_t raw_len = snap->raw_request_line_len;
            std::string version_suffix;
            const char* const version_str = version_id_to_str(snap->version_id);

            if (version_str and raw_len >= HX_REQUEST_LINE_SUFFIX_LEN and
                memcmp(raw + raw_len - HX_REQUEST_LINE_SUFFIX_LEN, " HTTP/1.1", HX_REQUEST_LINE_SUFFIX_LEN) == 0)
            {
                raw_len -= HX_REQUEST_LINE_SUFFIX_LEN;
                version_suffix = " HTTP/";
                version_suffix.append(version_str);
            }

            const int32_t escape_budget = MAX_REQUEST_LINE_LOG_LEN - static_cast<int32_t>(version_suffix.length());
            append_escaped(out, raw, raw_len, std::max(escape_budget, 0));
            out.append(version_suffix);

            return;
        }

        if (has_section() and append_rebuilt_raw_request_line(out, section, MAX_REQUEST_LINE_LOG_LEN))
            return;

        out.append("<no request>");
    }

    static Bytes from_field(const Field& f)
    {
        if (f.length() < 0)
            return {};
        return { f.start(), static_cast<unsigned>(f.length()), true };
    }

    // Snapshots only carry request-limit evidence; method and header fields need a live section.
    Bytes method() const
    {
        if (has_section())
            return from_field(section->get_classic_buffer(HTTP_BUFFER_METHOD, 0, 0));

        return {};
    }

    Bytes user_agent() const
    {
        if (has_section())
            return from_field(section->get_classic_buffer(HTTP_BUFFER_HEADER, HEAD_USER_AGENT, 0));

        return {};
    }

    Bytes referer() const
    {
        if (has_section())
            return from_field(section->get_classic_buffer(HTTP_BUFFER_HEADER, HEAD_REFERER, 0));

        return {};
    }
};

static void fill_slot_from_bytes(HttpTmpBuffer& slot, HttpBufferSource::Bytes b)
{
    if (!b.present)
    {
        slot.field.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
        return;
    }

    slot.text.clear();
    if (b.len > 0)
        append_escaped(slot.text, b.data, static_cast<int32_t>(b.len),
            static_cast<int32_t>(b.len) * 4);
    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_decoded_uri(const HttpBufferSource& src, HttpTmpBufferCache& tmp_cache,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    if (src.has_section())
    {
        HttpMsgRequest* req = src.section->get_request();
        if (req)
        {
            HttpUri* uri = req->get_http_uri();
            if (uri)
            {
                uri->fill_decoded_uri(slot.field, tmp_cache.decoded_path);
                return;
            }
        }
    }

    slot.field.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
    tmp_cache.decoded_path.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
}

static void compute_method_str(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    fill_slot_from_bytes(slot, src.method());
}

static void compute_request_size(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    slot.num = src.request_size();
    slot.field.set(sizeof(uint32_t), reinterpret_cast<const uint8_t*>(&slot.num));
}

static void compute_request_line_length(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    uint32_t length;
    if (!src.request_line_length(length))
    {
        slot.field.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
        return;
    }
    slot.num = length;
    slot.field.set(sizeof(uint32_t), reinterpret_cast<const uint8_t*>(&slot.num));
}

static void compute_response_size(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    if (!src.has_section())
    {
        slot.field.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
        return;
    }

    const HttpTransaction* txn = src.section->get_transaction();
    const uint64_t val = txn->get_message_length(txn->get_status(), HttpCommon::SRC_SERVER);

    slot.num = val > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(val);
    slot.field.set(sizeof(uint32_t), reinterpret_cast<const uint8_t*>(&slot.num));
}

static void fill_slot_from_version_id(HttpTmpBuffer& slot, VersionId version)
{
    const char* const version_str = version_id_to_str(version);
    if (!version_str)
    {
        slot.field.set(static_cast<HttpCommon::StatusCode>(STAT_NOT_PRESENT));
        return;
    }

    slot.text = "HTTP/";
    slot.text.append(version_str);
    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_version_str(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo& buf)
{
    if (src.has_any_snapshot())
    {
        // Snapshots keep only the parsed version id, not raw version bytes.
        fill_slot_from_version_id(slot, src.wire.best()->version_id);
        return;
    }
    assert(src.has_section());

    fill_slot_from_version_id(slot, src.section->get_version_id(buf));
}

static void compute_user_agent_str(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    fill_slot_from_bytes(slot, src.user_agent());
}

static void compute_referer_str(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    fill_slot_from_bytes(slot, src.referer());
}

static void compute_detail_119_20(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo& buf)
{
    // EVENT_MAX_HEADERS
    // Header Count: XXX
    slot.text = "Header Count: ";
    auto cnt = src.section->get_num_headers(buf);
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

static void compute_detail_119_287(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    // EVENT_DISALLOWED_METHOD
    // HTTP Method: XXX
    slot.text = "HTTP Method: ";
    const Field& method = src.section->get_classic_buffer(HTTP_BUFFER_METHOD, 0, 0);
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

static void compute_detail_119_298(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    // EVENT_REQUEST_SIZE_TOO_LONG
    // Request Size: XXX
    slot.text = "Request Size: " + std::to_string(src.request_size());
    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_299(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    // EVENT_REQUEST_LINE_LENGTH_TOO_LONG
    // Request Line Length: XXX
    uint32_t request_line_length = 0;
    src.request_line_length_detail(request_line_length);

    slot.text = "Request Line Length: " +
        std::to_string(request_line_length) + ", Request Line: ";

    src.append_raw_request_line(slot.text, src.wire.for_299());
    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_300(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    // EVENT_REQUEST_LINE_NOT_VALID
    // XXX, Request Line: YYY
    slot.text = get_http_event_reason_msg(src.request_line_invalid_reason());
    slot.text.append(", Request Line: ");

    src.append_raw_request_line(slot.text, src.wire.for_300());
    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_301(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    // EVENT_HEADER_INVALID_CL_OR_TE
    // <reason>[, Content-Length: XXX][, Transfer-Encoding: YYY]
    const auto code = static_cast<Detail301ReasonCode>(slot.num);

    slot.text = get_detail_301_reason(code);

    switch ( code )
    {
    case DETAIL_301_NONE:
        break;
    case DETAIL_301_CL_AND_TE_PRESENT:
        append_header_value(slot.text, ", Content-Length: ", src.section, HEAD_CONTENT_LENGTH);
        append_header_value(slot.text, ", Transfer-Encoding: ", src.section, HEAD_TRANSFER_ENCODING);
        break;
    case DETAIL_301_NEGATIVE_CL:
        append_header_value(slot.text, ", Content-Length: ", src.section, HEAD_CONTENT_LENGTH);
        break;
    case DETAIL_301_HTTPX_HAS_TE:
        append_header_value(slot.text, ", Transfer-Encoding: ", src.section, HEAD_TRANSFER_ENCODING);
        break;
    }

    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_304(const HttpBufferSource&, HttpTmpBufferCache& tmp_cache,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    // EVENT_UNSAFE_CHARACTERS_IN_HEADER
    // Unsafe Header: <escaped header bytes>
    static constexpr int32_t max_unsafe_header_log_len = 256;
    const Field& raw_header = tmp_cache.unsafe_header;

    if (raw_header.length() <= 0)
        slot.text = "No header detail available";
    else
    {
        slot.text = "Unsafe Header: ";
        const int32_t detail_budget =
            max_unsafe_header_log_len - static_cast<int32_t>(slot.text.length());
        append_header_detail(slot.text, raw_header.start(), raw_header.length(),
            std::max(detail_budget, 0));
    }

    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_305(const HttpBufferSource&, HttpTmpBufferCache& tmp_cache,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    // EVENT_MALFORMED_HEADER
    // Malformed Header: <escaped header bytes>
    constexpr int32_t MAX_MALFORMED_HEADER_LOG_LEN = 256;
    const Field& header_line = tmp_cache.malformed_header;

    if (header_line.length() <= 0)
        slot.text = "No header detail available";
    else
    {
        slot.text = "Malformed Header: ";
        const int32_t detail_budget =
            MAX_MALFORMED_HEADER_LOG_LEN - static_cast<int32_t>(slot.text.length());
        append_header_detail(slot.text, header_line.start(), header_line.length(),
            std::max(detail_budget, 0));
    }

    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

static void compute_detail_119_306(const HttpBufferSource& src, HttpTmpBufferCache&,
    HttpTmpBuffer& slot, const HttpBufferInfo&)
{
    // EVENT_CONTENT_TYPE_NOT_ALLOWED
    // Content Type: XXX
    static constexpr int32_t max_content_type_log_len = 256;

    assert(src.section);
    // Raw value: the normalized one drops quotes and lowercases the case-sensitive boundary
    const Field& value = src.section->get_classic_buffer(HTTP_BUFFER_RAW_HEADER,
        HEAD_CONTENT_TYPE, 0);

    slot.text = "Content Type: ";
    append_content_type_detail(slot.text, value.start(), value.length(),
        max_content_type_log_len);

    slot.field.set(static_cast<int32_t>(slot.text.length()),
        reinterpret_cast<const uint8_t*>(slot.text.c_str()));
}

// ---------------------------------------------------------------------------
// Descriptor table and shared materializer
// ---------------------------------------------------------------------------

using TmpComputeFn = void(*)(const HttpBufferSource&, HttpTmpBufferCache&, HttpTmpBuffer&,
    const HttpBufferInfo&);

struct TmpBufferDescriptor
{
    TmpComputeFn compute;

    // Can this buffer be materialized from splitter-time snapshots?
    bool wire_reportable;
};

static const TmpBufferDescriptor tmp_buffer_desc[HTTP_TMP_BUFFER_CNT] =
{
    { compute_decoded_uri,          false }, // HTTP_BUFFER_DECODED_URI
    { compute_method_str,           true  }, // HTTP_BUFFER_METHOD_STR
    { compute_request_size,         true  }, // HTTP_BUFFER_REQUEST_SIZE
    { compute_request_line_length,  true  }, // HTTP_BUFFER_REQUEST_LINE_LENGTH
    { compute_response_size,        true  }, // HTTP_BUFFER_RESPONSE_SIZE
    { compute_version_str,          true  }, // HTTP_BUFFER_VERSION_STR
    { compute_user_agent_str,       true  }, // HTTP_BUFFER_USER_AGENT_STR
    { compute_referer_str,          true  }, // HTTP_BUFFER_REFERER_STR
    { compute_detail_119_20,        false }, // DETAIL_119_20
    { compute_detail_119_287,       false }, // DETAIL_119_287
    { compute_detail_119_298,       true  }, // DETAIL_119_298
    { compute_detail_119_299,       true  }, // DETAIL_119_299
    { compute_detail_119_300,       true  }, // DETAIL_119_300
    { compute_detail_119_301,       false }, // DETAIL_119_301
    { compute_detail_119_304,       false }, // DETAIL_119_304
    { compute_detail_119_305,       false }, // DETAIL_119_305
    { compute_detail_119_306,       false }, // DETAIL_119_306
};

static const Field& materialize(const HttpBufferSource& src, const HttpBufferInfo& buf)
{
    if (buf.type <= HttpEnums::HTTP__BUFFER_MAX or buf.type > HttpEnums::HTTP__TMP_BUFFER_MAX)
        return Field::FIELD_NULL;

    const unsigned index = buf.type - HTTP_FIRST_TMP_BUFFER;
    assert(index < HTTP_TMP_BUFFER_CNT);
    const TmpBufferDescriptor& desc = tmp_buffer_desc[index];

    if (!src.has_section() and !src.has_any_snapshot())
        return Field::FIELD_NULL;

    if (src.has_any_snapshot() and !desc.wire_reportable)
        return Field::FIELD_NULL;

    HttpTmpBufferCache& tmp_cache = HttpContextData::get_tmp_buffers();
    if (!tmp_cache.tmp_bufs[index])
        tmp_cache.tmp_bufs[index] = std::make_unique<HttpTmpBuffer>();

    HttpTmpBuffer& slot = *tmp_cache.tmp_bufs[index];
    if (slot.field.length() == STAT_NOT_COMPUTE)
        desc.compute(src, tmp_cache, slot, buf);

    return slot.field;
}

const Field& get_http_tmp_buffer(const HttpBufferInfo& buf, HttpMsgSection* section)
{
    assert(section != nullptr);
    return materialize(HttpBufferSource{section, {}}, buf);
}

const Field& get_http_tmp_buffer(const HttpBufferInfo& buf,
    const HttpSplitterSnapshot* snap_300, const HttpSplitterSnapshot* snap_299,
    const HttpSplitterSnapshot* snap_298)
{
    return materialize(HttpBufferSource{nullptr, {snap_300, snap_299, snap_298}}, buf);
}

bool is_wire_reportable_buffer(unsigned buf_type)
{
    if (buf_type <= HttpEnums::HTTP__BUFFER_MAX or buf_type > HttpEnums::HTTP__TMP_BUFFER_MAX)
        return false;

    return tmp_buffer_desc[buf_type - HTTP_FIRST_TMP_BUFFER].wire_reportable;
}
