//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// http_msg_head_shared.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_head_shared.h"

#include "hash/hash_key_operations.h"
#include "utils/util_cstring.h"

#include "http_common.h"
#include "http_enum.h"
#include "http_msg_request.h"

using namespace HttpCommon;
using namespace HttpEnums;
using namespace snort;

HttpMsgHeadShared::HttpMsgHeadShared(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
    HttpCommon::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
    const HttpParaList* params_): HttpMsgSection(buffer, buf_size, session_data_, source_id_,
    buf_owner, flow_, params_), own_msg_buffer(buf_owner)
{ }

HttpMsgHeadShared::~HttpMsgHeadShared()
{
    delete[] header_line;
    delete[] header_name;
    delete[] header_name_id;
    delete[] header_value;
    NormalizedHeader* list_ptr = norm_heads;
    while (list_ptr != nullptr)
    {
        NormalizedHeader* temp_ptr = list_ptr;
        list_ptr = list_ptr->next;
        delete temp_ptr;
    }
}

int32_t HttpMsgHeadShared::get_content_type()
{
    if (content_type != STAT_NOT_COMPUTE)
        return content_type;

    const Field& content_type_hdr = get_header_value_norm(HEAD_CONTENT_TYPE);
    const uint8_t* start = content_type_hdr.start();
    int32_t len = content_type_hdr.length();

    if (len <= 0)
    {
        content_type = CT__OTHER;
        return content_type;
    }

    if (const uint8_t* semicolon = (const uint8_t*)memchr(start, ';', len))
        len = semicolon - start;

    content_type = str_to_code(start, len, content_type_list);
    return content_type;
}

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void HttpMsgHeadShared::analyze()
{
    parse_header_block();
    parse_header_lines();
    create_norm_head_list();
}

void HttpMsgHeadShared::create_norm_head_list()
{
    // This function does not do the actual JIT normalization of header values. It converts the
    // header names into numeric IDs and creates a linked list of all the different headers that
    // are present in the message along with the number of times each one appears.
    for (int j=0; j < num_headers; j++)
    {
        derive_header_name_id(j);
        if (header_name_id[j] > 0)
        {
            if (headers_present[header_name_id[j]])
            {
                NormalizedHeader* list_ptr;
                for (list_ptr = norm_heads; list_ptr->id != header_name_id[j];
                    list_ptr = list_ptr->next);
                list_ptr->count++;
            }
            else
            {
                headers_present[header_name_id[j]] = true;
                NormalizedHeader* tmp_ptr = norm_heads;
                norm_heads = new NormalizedHeader(tmp_ptr, 1, header_name_id[j]);
            }
        }
    }
}

// Divide up the block of header fields into individual header field lines.
void HttpMsgHeadShared::parse_header_block()
{
    int32_t bytes_used = 0;
    num_headers = 0;
    max_header_line = 0;
    int32_t num_seps;

    // The number of header lines in a message may be zero
    header_line = new Field[session_data->num_head_lines[source_id]];

    // session_data->num_head_lines is computed by HttpStreamSplitter without consideration of
    // wrapping and may occasionally overstate the actual number of headers. That was OK for
    // allocating space for the header_line array, but henceforth rely on num_headers which is
    // calculated correctly.
    while (bytes_used < msg_text.length())
    {
        const int32_t header_length = find_next_header(msg_text.start() + bytes_used,
            msg_text.length() - bytes_used, num_seps);
        if (header_length == 0)
            break;

        assert(num_headers < session_data->num_head_lines[source_id]);
        if (header_length >  max_header_line)
        {
            max_header_line = header_length;
        }
        header_line[num_headers].set(header_length, msg_text.start() + bytes_used + num_seps);
        if (header_line[num_headers].length() > params->maximum_header_length)
        {
            add_infraction(INF_TOO_LONG_HEADER);
            create_event(EVENT_LONG_HDR);
        }
        bytes_used += num_seps + header_line[num_headers].length();
        ++num_headers;
    }
    if (num_headers > params->maximum_headers)
    {
        add_infraction(INF_TOO_MANY_HEADERS);
        create_event(EVENT_MAX_HEADERS);
    }
}

// The header section produced by the splitter is of the form:
//
// [CRs]<header 1><separators><header 2><separators> ... <header N>
//
// where separators are CRs or LFs. The CRs at the beginning are a pathological case that will
// virtually never happen. There are no separators after the final header.
//
// This function splits out the next header from the header block. The return value is the length
// of the header without any separators. num_seps is the number of separators to skip over before
// the header starts.
//
// Wrapping is fully supported by http_inspect. Wrapping is deprecated by the RFC and some major
// browsers don't support it. Wrapped headers are very dangerous and should be regarded with
// extreme suspicion.
//
// Except for wrapping, header lines may end with CRLF (correct), LF (incorrect but widely
// tolerated), and CR without LF (very incorrect). The latter is widely supported but some major
// browsers don't support it*. Bare CR separators are very dangerous and should be regarded with
// extreme suspicion. The splitter detects them which is why there is no event generated here.
// Bare LFs are probably not a big deal.
//
// * Not necessarily the same ones that don't support wrapping.

// FIXIT-M Need to generate EVENT_EXCEEDS_SPACES for excessive white space within a header.

int32_t HttpMsgHeadShared::find_next_header(const uint8_t* buffer, int32_t length,
    int32_t& num_seps)
{
    int32_t k = 0;
    // Splitter guarantees buffer will not end on CR or LF.
    for (; is_cr_lf[buffer[k]]; k++);
    num_seps = k;

    for (k++; k < length; k++)
    {
        if (is_cr_lf[buffer[k]])
        {
            // Check for wrapping
            if (((buffer[k] == '\r') && (buffer[k+1] == '\n') && !is_sp_tab[buffer[k+2]]) ||
                ((buffer[k] == '\n') && !is_sp_tab[buffer[k+1]]) ||
                ((buffer[k] == '\r') && !is_sp_tab_lf[buffer[k+1]]))
            {
                return k - num_seps;
            }
            else
            {
                add_infraction(INF_HEADER_WRAPPING);
                create_event(EVENT_HEADER_WRAPPING);
            }
        }
    }
    if (session_data->partial_flush[source_id] && session_data->num_excess[source_id] == 0)
        return 0;
    return length - num_seps;
}

// Divide header field lines into field name and field value
void HttpMsgHeadShared::parse_header_lines()
{
    header_name = new Field[num_headers];
    header_value = new Field[num_headers];
    header_name_id = new HeaderId[num_headers];

    for (int k=0; k < num_headers; k++)
    {
        int colon;
        for (colon=0; colon < header_line[k].length(); colon++)
        {
            if (header_line[k].start()[colon] == ':')
                break;
        }
        if (colon < header_line[k].length())
        {
            header_name[k].set(colon, header_line[k].start());
            header_value[k].set(header_line[k].length() - colon - 1,
                                header_line[k].start() + colon + 1);
        }
        else
        {
            add_infraction(INF_BAD_HEADER);
            create_event(EVENT_BAD_HEADER);
            header_name[k].set(STAT_PROBLEMATIC);
            header_value[k].set(STAT_PROBLEMATIC);
        }
    }
}

void HttpMsgHeadShared::derive_header_name_id(int index)
{
    const int32_t length = header_name[index].length();
    const uint8_t* buffer = header_name[index].start();

    if (length <= 0)
    {
        header_name_id[index] = HEAD__PROBLEMATIC;
        return;
    }

    // Normalize header field name to lower case and remove LWS for matching purposes
    int32_t lower_length = 0;
    uint8_t* lower_name = new uint8_t[length];
    for (int32_t k=0; k < length; k++)
    {
        if (!is_sp_tab_cr_lf[buffer[k]])
        {
            lower_name[lower_length++] = ((buffer[k] < 'A') || (buffer[k] > 'Z')) ?
                buffer[k] : buffer[k] - ('A' - 'a');
            if (!is_print_char[buffer[k]])
            {
                add_infraction(INF_BAD_CHAR_IN_HEADER_NAME);
                create_event(EVENT_BAD_CHAR_IN_HEADER_NAME);
            }
        }
        else
        {
            add_infraction(INF_HEAD_NAME_WHITESPACE);
            create_event(EVENT_HEAD_NAME_WHITESPACE);
        }
    }
    header_name_id[index] = (HeaderId)str_to_code(lower_name, lower_length, params->header_list);
    delete[] lower_name;
}

NormalizedHeader* HttpMsgHeadShared::get_header_node(HeaderId header_id) const
{
    if (!headers_present[header_id])
        return nullptr;

    NormalizedHeader* list_ptr;
    for (list_ptr = norm_heads; list_ptr->id != header_id; list_ptr = list_ptr->next);
    return (list_ptr);
}

int HttpMsgHeadShared::get_header_count(HeaderId header_id) const
{
    NormalizedHeader* node = get_header_node(header_id);
    return (node != nullptr) ? node->count : 0;
}

const Field& HttpMsgHeadShared::get_classic_raw_header()
{
    if (classic_raw_header.length() != STAT_NOT_COMPUTE)
        return classic_raw_header;
    const HeaderId cookie_head = (source_id == SRC_CLIENT) ? HEAD_COOKIE : HEAD_SET_COOKIE;
    if (!headers_present[cookie_head])
    {
        // There are no cookies so the classic headers are the whole thing
        classic_raw_header.set(msg_text);
        return classic_raw_header;
    }

    // Figure out how much space to allocate by stepping through the headers in advance
    int32_t length = 0;
    for (int k = 0; k < num_headers; k++)
    {
        if (header_name_id[k] == cookie_head)
            continue;
        // All header line Fields point into the buffer holding the entire message section.
        // Calculation must account for separators between header lines, but there are none
        // following the final header line.
        const int32_t head_len = (k == num_headers-1) ? header_line[k].length() :
            header_line[k+1].start() - header_line[k].start();
        length += head_len;
    }

    // Step through headers again and do the copying this time
    uint8_t* const buffer = new uint8_t[length];
    int32_t current = 0;
    for (int k = 0; k < num_headers; k++)
    {
        if (header_name_id[k] == cookie_head)
            continue;
        const int32_t head_len = (k == num_headers-1) ? header_line[k].length() :
            header_line[k+1].start() - header_line[k].start();
        memcpy(buffer + current, header_line[k].start(), head_len);
        current += head_len;
    }
    assert(current == length);

    classic_raw_header.set(length, buffer, true);
    return classic_raw_header;
}

const Field& HttpMsgHeadShared::get_classic_norm_header()
{
    return classic_normalize(get_classic_raw_header(), classic_norm_header,
        false, params->uri_param);
}

const Field& HttpMsgHeadShared::get_classic_raw_cookie()
{
    HeaderId cookie_head = (source_id == SRC_CLIENT) ? HEAD_COOKIE : HEAD_SET_COOKIE;
    return get_header_value_norm(cookie_head);
}

const Field& HttpMsgHeadShared::get_classic_norm_cookie()
{
    return classic_normalize(get_classic_raw_cookie(), classic_norm_cookie,
        false, params->uri_param);
}

const Field& HttpMsgHeadShared::get_header_value_raw(HeaderId header_id) const
{
    // If the same header field appears more than once the first one will be returned.
    if (!headers_present[header_id])
        return Field::FIELD_NULL;
    for (int k=0; k < num_headers; k++)
    {
        if (header_name_id[k] == header_id)
        {
            return header_value[k];
        }
    }
    assert(false);
    return Field::FIELD_NULL;
}

// Get raw header values. If the same header field appears more than once the
// values are converted into a comma-separated list
const Field& HttpMsgHeadShared::get_all_header_values_raw(HeaderId header_id)
{
    NormalizedHeader* node = get_header_node(header_id);
    if (node == nullptr)
        return Field::FIELD_NULL;

    return node->get_comma_separated_raw(*this, transaction->get_infractions(source_id),
        session_data->events[source_id], header_name_id, header_value, num_headers);
}

const Field& HttpMsgHeadShared::get_header_value_norm(HeaderId header_id)
{
    NormalizedHeader* node = get_header_node(header_id);
    if (node == nullptr)
        return Field::FIELD_NULL;

    return node->get_norm(transaction->get_infractions(source_id),
        session_data->events[source_id], header_name_id, header_value, num_headers);
}

// For downloads we use the hash of the URL if it exists. For uploads we use a hash of the filename
// parameter in the Content-Disposition header, if one exists. Otherwise the file_index is 0,
// meaning the file verdict will not be cached.
uint64_t HttpMsgHeadShared::get_file_cache_index()
{
    if (file_cache_index_computed)
        return file_cache_index;

    if (source_id == SRC_SERVER)
    {
        if ((request != nullptr) and (request->get_http_uri() != nullptr))
        {
            const Field& abs_path = request->get_http_uri()->get_abs_path();
            if (abs_path.length() > 0)
            {
                file_cache_index = str_to_hash(abs_path.start(), abs_path.length());
            }
        }
    }
    else
    {
        const Field& cd_filename = get_content_disposition_filename();
        if (cd_filename.length() > 0)
            file_cache_index = str_to_hash(cd_filename.start(), cd_filename.length());
    }
    file_cache_index_computed = true;

    return file_cache_index;
}

const Field& HttpMsgHeadShared::get_content_disposition_filename()
{
    if (content_disposition_filename.length() == STAT_NOT_COMPUTE)
        extract_filename_from_content_disposition();

    return content_disposition_filename;
}

// Extract the filename from the content-disposition header
void HttpMsgHeadShared::extract_filename_from_content_disposition()
{
    const Field& cont_disp = get_header_value_raw(HEAD_CONTENT_DISPOSITION);

    const uint8_t* cur = cont_disp.start();
    const uint8_t* const end = cont_disp.start() + cont_disp.length();
    const uint8_t* fname_begin = nullptr;
    const uint8_t* fname_end = nullptr;
    bool char_set = false;
    enum {
        CD_STATE_START,
        CD_STATE_BEFORE_VAL,
        CD_STATE_VAL,
        CD_STATE_QUOTED_VAL,
        CD_STATE_BEFORE_EXT_VAL,
        CD_STATE_CHARSET,
        CD_STATE_LANGUAGE,
        CD_STATE_EXT_VAL,
        CD_STATE_FINAL,
        CD_STATE_PROBLEM
    };
    const char *cd_file1 = "filename";
    const char *cd_file2 = "filename*";
    const char* filename_str_start = nullptr;

    if (cont_disp.length() <= 0)
    {
        content_disposition_filename.set(STAT_NOT_PRESENT);
        return;
    }
    uint8_t state = CD_STATE_START;

    while (cur < end and state != CD_STATE_PROBLEM)
    {
        switch (state)
        {
            case CD_STATE_START:
                if ((filename_str_start = SnortStrcasestr((const char*)cur, end - cur, cd_file2)))
                {
                    state = CD_STATE_BEFORE_EXT_VAL;
                    cur = (const uint8_t*)filename_str_start + strlen(cd_file2) - 1;
                }
                else if ((filename_str_start = SnortStrcasestr((const char*)cur, end - cur,
                    cd_file1)))
                {
                    state = CD_STATE_BEFORE_VAL;
                    cur = (const uint8_t*)filename_str_start + strlen(cd_file1) - 1;
                }
                else
                {
                    content_disposition_filename.set(STAT_NOT_PRESENT);
                    return;
                }
                break;
            case CD_STATE_BEFORE_VAL:
                if (*cur == '=')
                    state = CD_STATE_VAL;
                else if (*cur != ' ')
                    state = CD_STATE_START;
                break;
            case CD_STATE_VAL:
                if (!fname_begin && *cur == '"')
                    state = CD_STATE_QUOTED_VAL;
                else if (*cur == ';' || *cur == '\r' || *cur == '\n' || *cur == ' ' || *cur == '\t')
                {
                    if (fname_begin)
                    {
                        fname_end = cur;
                        state =  CD_STATE_FINAL;
                    }
                }
                else if (!fname_begin)
                    fname_begin = cur;
                break;
            case CD_STATE_QUOTED_VAL:
                if (!fname_begin)
                    fname_begin = cur;
                if (*cur == '"' )
                {
                    fname_end = cur;
                    state =  CD_STATE_FINAL;
                }
                break;
            case CD_STATE_BEFORE_EXT_VAL:
                if (*cur == '=')
                    state = CD_STATE_CHARSET;
                else if (*cur != ' ')
                    state = CD_STATE_START;
                break;
            case CD_STATE_CHARSET:
                if (*cur == '\'')
                {
                    if (!char_set)
                    {
                        state = CD_STATE_PROBLEM;
                        break;
                    }
                    else
                        state = CD_STATE_LANGUAGE;
                }
                else if (!char_set)
                {
                    // Ignore space before the ext-value
                    while (cur < end && *cur == ' ')
                        cur++;
                    if (cur < end)
                    {
                        if (!strncasecmp((const char*) cur, "UTF-8", 5))
                            cur += 5;
                        else if (!strncasecmp((const char*) cur, "ISO-8859-1", 10))
                            cur += 10;
                        else if (!strncasecmp((const char*) cur, "mime-charset", 12))
                            cur += 12;
                        else
                        {
                            state = CD_STATE_PROBLEM;
                            break;
                        }
                        char_set = true;
                        continue;
                    }
                }
                else
                {
                    state = CD_STATE_PROBLEM;
                    break;
                }
                break;
            case CD_STATE_LANGUAGE:
                if (*cur == '\'')
                    state = CD_STATE_EXT_VAL;
                break;
            case CD_STATE_EXT_VAL:
                if(*cur == ';' || *cur == '\r' || *cur == '\n' || *cur == ' ' || *cur == '\t')
                {
                    fname_end = cur;
                    state = CD_STATE_FINAL;
                }
                else if (!fname_begin)
                    fname_begin = cur;
                break;
            case CD_STATE_FINAL:
                if (fname_begin && fname_end)
                {
                    content_disposition_filename.set(fname_end-fname_begin, fname_begin);
                    return;
                }
                // fallthrough
            default:
                state = CD_STATE_PROBLEM;
                break;
        }
        cur++;
    }
    switch (state)
    {
        case CD_STATE_FINAL:
        case CD_STATE_VAL:
        case CD_STATE_EXT_VAL:
            if (fname_begin)
            {
                if (!fname_end)
                    fname_end = end;
                content_disposition_filename.set(fname_end-fname_begin, fname_begin);
                break;
            }
            // fallthrough
        default:
            add_infraction(INF_MALFORMED_CD_FILENAME);
            create_event(EVENT_MALFORMED_CD_FILENAME);
            content_disposition_filename.set(STAT_PROBLEMATIC);
            break;
    }
}

#ifdef REG_TEST
void HttpMsgHeadShared::print_headers(FILE* output)
{
    char title_buf[100];
    if (num_headers != STAT_NO_SOURCE)
        fprintf(output, "Number of headers: %d\n", num_headers);
    for (int j=0; j < num_headers; j++)
    {
        snprintf(title_buf, sizeof(title_buf), "Header ID %d", header_name_id[j]);
        header_value[j].print(output, title_buf);
    }
    for (int k=1; k <= HEAD__MAX_VALUE-1; k++)
    {
        if (get_header_value_norm((HeaderId)k).length() != STAT_NO_SOURCE)
        {
            snprintf(title_buf, sizeof(title_buf), "Normalized header %d", k);
            get_header_value_norm((HeaderId)k).print(output, title_buf);
        }
    }
}
#endif

