//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// http_normalized_header.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_normalized_header.h"

#include "http_common.h"
#include "http_enum.h"
#include "http_msg_head_shared.h"
#include "http_normalizers.h"

#include <cstring>

using namespace HttpCommon;
using namespace HttpEnums;

//-------------------------------------------------------------------------
// HeaderNormalizer class
// Strategies for normalizing HTTP header field values
//-------------------------------------------------------------------------

// Three normalization functions per HeaderNormalizer seems likely to be enough. Nothing subtle
// will break if you choose to expand it to four or more. Just a whole bunch of signatures and
// initializers to update. When defining a HeaderNormalizer don't leave holes in the normalizer
// list. E.g. if you have two normalizers they must be first and second. If you do first and third
// instead it won't explode but the third one won't be used either.

class NormalizedHeader::HeaderNormalizer
{
public:
    constexpr HeaderNormalizer(HttpEnums::EventSid _repeat_event,
        HttpEnums::Infraction _repeat_inf, bool _alert_ws,
        NormFunc* f1, NormFunc* f2, NormFunc* f3)
        : repeat_event(_repeat_event), repeat_inf(_repeat_inf), alert_ws(_alert_ws),
        normalizer { f1, f2, f3 },
        num_normalizers((f1 != nullptr) + (f1 != nullptr)*(f2 != nullptr) + (f1 != nullptr)*(f2 !=
            nullptr)*(f3 != nullptr)) { }

    void normalize(const HttpEnums::HeaderId head_id, const int count,
        HttpInfractions* infractions, HttpEventGen* events,
        const HttpEnums::HeaderId header_name_id[], const Field header_value[],
        const int32_t num_headers, Field& result_field, Field& comma_separated_raw) const;

private:
    const HttpEnums::EventSid repeat_event;
    const HttpEnums::Infraction repeat_inf;
    const bool alert_ws;  // alert if white space in middle of value
    NormFunc* const normalizer[3];
    const int num_normalizers;
};

const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_BASIC
    { EVENT__NONE, INF__NONE, false, nullptr, nullptr, nullptr };

const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_HOST
    { EVENT_MULTIPLE_HOST_HDRS, INF_MULTIPLE_HOST_HDRS, false, nullptr, nullptr, nullptr };

const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_CASE_INSENSITIVE
    { EVENT__NONE, INF__NONE, false, norm_to_lower, nullptr, nullptr };

const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_NUMBER
    { EVENT_REPEATED_HEADER, INF_REPEATED_HEADER, false, norm_remove_lws, nullptr, nullptr };

const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_TOKEN_LIST
    { EVENT__NONE, INF__NONE, false, norm_remove_lws, norm_to_lower, nullptr };

const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_METHOD_LIST
    { EVENT__NONE, INF__NONE, false, norm_remove_lws, nullptr, nullptr };

// FIXIT-L implement a date normalization function that converts the three legal formats into a
// single standard format. For now we do nothing special for dates. This object is a placeholder
// to keep track of which headers have date values.
const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_DATE
    { EVENT__NONE, INF__NONE, false, nullptr, nullptr, nullptr };

// FIXIT-M implement a URI normalization function, probably by extending existing URI capabilities
// to cover relative formats
const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_URI
    { EVENT__NONE, INF__NONE, false, nullptr, nullptr, nullptr };

const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_CONTENT_LENGTH
    { EVENT_MULTIPLE_CONTLEN, INF_MULTIPLE_CONTLEN, true, norm_remove_lws, nullptr, nullptr };

const NormalizedHeader::HeaderNormalizer NormalizedHeader::NORMALIZER_CHARSET
    { EVENT__NONE, INF__NONE, false, norm_remove_quotes_lws, norm_to_lower, nullptr };

const NormalizedHeader::HeaderNormalizer* const NormalizedHeader::header_norms[HEAD__MAX_VALUE + MAX_CUSTOM_HEADERS + 1] = {
    &NORMALIZER_BASIC,      // 0
    &NORMALIZER_BASIC,      // HEAD__OTHER
    &NORMALIZER_TOKEN_LIST, // HEAD_CACHE_CONTROL
    &NORMALIZER_TOKEN_LIST, // HEAD_CONNECTION
    &NORMALIZER_DATE,       // HEAD_DATE
    &NORMALIZER_TOKEN_LIST, // HEAD_PRAGMA
    &NORMALIZER_TOKEN_LIST, // HEAD_TRAILER
    &NORMALIZER_BASIC,      // HEAD_COOKIE
    &NORMALIZER_BASIC,      // HEAD_SET_COOKIE
    &NORMALIZER_TOKEN_LIST, // HEAD_TRANSFER_ENCODING
    &NORMALIZER_TOKEN_LIST, // HEAD_UPGRADE
    &NORMALIZER_BASIC,      // HEAD_VIA
    &NORMALIZER_BASIC,      // HEAD_WARNING
    &NORMALIZER_TOKEN_LIST, // HEAD_ACCEPT
    &NORMALIZER_TOKEN_LIST, // HEAD_ACCEPT_CHARSET
    &NORMALIZER_TOKEN_LIST, // HEAD_ACCEPT_ENCODING
    &NORMALIZER_TOKEN_LIST, // HEAD_ACCEPT_LANGUAGE
    &NORMALIZER_BASIC,      // HEAD_AUTHORIZATION
    &NORMALIZER_CASE_INSENSITIVE, // HEAD_EXPECT
    &NORMALIZER_BASIC,      // HEAD_FROM
    &NORMALIZER_HOST,       // HEAD_HOST
    &NORMALIZER_BASIC,      // HEAD_IF_MATCH
    &NORMALIZER_DATE,       // HEAD_IF_MODIFIED_SINCE
    &NORMALIZER_BASIC,      // HEAD_IF_NONE_MATCH
    &NORMALIZER_BASIC,      // HEAD_IF_RANGE
    &NORMALIZER_DATE,       // HEAD_IF_UNMODIFIED_SINCE
    &NORMALIZER_BASIC,      // HEAD_MAX_FORWARDS
    &NORMALIZER_BASIC,      // HEAD_PROXY_AUTHORIZATION
    &NORMALIZER_BASIC,      // HEAD_RANGE
    &NORMALIZER_URI,        // HEAD_REFERER
    &NORMALIZER_TOKEN_LIST, // HEAD_TE
    &NORMALIZER_BASIC,      // HEAD_USER_AGENT
    &NORMALIZER_TOKEN_LIST, // HEAD_ACCEPT_RANGES
    &NORMALIZER_NUMBER,     // HEAD_AGE
    &NORMALIZER_BASIC,      // HEAD_ETAG
    &NORMALIZER_URI,        // HEAD_LOCATION
    &NORMALIZER_BASIC,      // HEAD_PROXY_AUTHENTICATE
    &NORMALIZER_BASIC,      // HEAD_RETRY_AFTER, may be date or number
    &NORMALIZER_BASIC,      // HEAD_SERVER
    &NORMALIZER_TOKEN_LIST, // HEAD_VARY
    &NORMALIZER_BASIC,      // HEAD_WWW_AUTHENTICATE
    &NORMALIZER_METHOD_LIST, // HEAD_ALLOW
    &NORMALIZER_TOKEN_LIST, // HEAD_CONTENT_ENCODING
    &NORMALIZER_TOKEN_LIST, // HEAD_CONTENT_LANGUAGE
    &NORMALIZER_CONTENT_LENGTH, // HEAD_CONTENT_LENGTH
    &NORMALIZER_URI,        // HEAD_CONTENT_LOCATION
    &NORMALIZER_BASIC,      // HEAD_CONTENT_MD5
    &NORMALIZER_BASIC,      // HEAD_CONTENT_RANGE
    &NORMALIZER_CHARSET,    // HEAD_CONTENT_TYPE
    &NORMALIZER_DATE,       // HEAD_EXPIRES
    &NORMALIZER_DATE,       // HEAD_LAST_MODIFIED
    &NORMALIZER_BASIC,      // HEAD_X_FORWARDED_FOR
    &NORMALIZER_BASIC,      // HEAD_TRUE_CLIENT_IP
    &NORMALIZER_BASIC,      // HEAD_X_WORKING_WITH
    &NORMALIZER_TOKEN_LIST, // HEAD_CONTENT_TRANSFER_ENCODING
    &NORMALIZER_BASIC,      // HEAD_MIME_VERSION
    &NORMALIZER_BASIC,      // HEAD_PROXY_AGENT
    &NORMALIZER_BASIC,      // HEAD_CONTENT_DISPOSITION
    &NORMALIZER_TOKEN_LIST, // HEAD_HTTP2_SETTINGS
    &NORMALIZER_BASIC,      // HEAD_RESTRICT_ACCESS_TO_TENANTS
    &NORMALIZER_BASIC,      // HEAD_RESTRICT_ACCESS_CONTEXT
    &NORMALIZER_URI,        // HEAD_ORIGIN
    &NORMALIZER_BASIC,      // HEAD_FORWARDED
    &NORMALIZER_BASIC,      // HEAD_X_FORWARDED_FROM
    &NORMALIZER_BASIC,      // HEAD_CLIENT_IP
    &NORMALIZER_BASIC,      // HEAD_XROXY_CONNECTION
    &NORMALIZER_BASIC,      // HEAD_PROXY_CONNECTION
    &NORMALIZER_BASIC,      // HEAD__MAX_VALUE
    &NORMALIZER_BASIC,      // HEAD_CUSTOM_XFF_HEADER
    &NORMALIZER_BASIC,      // HEAD_CUSTOM_XFF_HEADER
    &NORMALIZER_BASIC,      // HEAD_CUSTOM_XFF_HEADER
    &NORMALIZER_BASIC,      // HEAD_CUSTOM_XFF_HEADER
    &NORMALIZER_BASIC,      // HEAD_CUSTOM_XFF_HEADER
    &NORMALIZER_BASIC,      // HEAD_CUSTOM_XFF_HEADER
    &NORMALIZER_BASIC,      // HEAD_CUSTOM_XFF_HEADER
    &NORMALIZER_BASIC,      // HEAD_CUSTOM_XFF_HEADER
};

// This derivation removes leading and trailing linear white space and replaces internal strings of
// linear whitespace with a single <SP>
static int32_t derive_header_content(const uint8_t* value, int32_t length, uint8_t* buffer,
    bool alert_ws, HttpInfractions* infractions, HttpEventGen* events)
{
    int32_t out_length = 0;
    bool beginning = true;
    bool last_white = true;
    for (int32_t k=0; k < length; k++)
    {
        if (!is_sp_tab_cr_lf[value[k]])
        {
            if (alert_ws && last_white && !beginning)
            {
                // white space which is not at beginning or end
                *infractions += INF_BAD_HEADER_WHITESPACE;
                events->create_event(EVENT_BAD_HEADER_WHITESPACE);
            }
            beginning = false;
            last_white = false;
            buffer[out_length++] = value[k];
        }
        else if (!last_white)
        {
            last_white = true;
            buffer[out_length++] = ' ';
        }
    }
    if ((out_length > 0) && (buffer[out_length - 1] == ' '))
    {
        out_length--;
    }
    return out_length;
}

// This method normalizes the header field value for headId.
void NormalizedHeader::HeaderNormalizer::normalize(const HeaderId head_id, const int count,
    HttpInfractions* infractions, HttpEventGen* events, const HeaderId header_name_id[],
    const Field header_value[], const int32_t num_headers, Field& result_field,
    Field& comma_separated_raw) const
{
    assert(count > 0);

    // Search Header IDs from all the headers in this message. All repeated field values are
    // concatenated into a comma-separated list.
    // FIXIT-L Set-Cookie is a special case in the RFC because multiple Set-Cookie headers are
    // widely used but comma-concatenation of cookies is incorrect. That would be a concern for us
    // if we actually used the cookies. But since we just want a single value to show to the
    // pattern matcher, concatenating is probably fine. In the future we may wish to revisit this
    // issue. Specifically, semicolon-concatenation may be better.
    int num_matches = 0;
    int32_t buffer_length = 0;

    // FIXIT-P initialization that serves no functional purpose to prevent compiler warning
    int curr_match = -1;
    for (int k=0; k < num_headers; k++)
    {
        if (header_name_id[k] == head_id)
        {
            if (++num_matches == 1)
                curr_match = k;   // remembering location of the first matching header
            buffer_length += header_value[k].length();
            if (num_matches >= count)
                break;
        }
    }
    assert(num_matches == count);
    buffer_length += num_matches - 1;    // allow space for concatenation commas

    // We are allocating two buffers to store the normalized field value. The raw field value will
    // be copied into one of them. Concatenation and white space normalization happen during this
    // step. Next a series of normalization functions will transform the value into final form.
    // Each normalization copies the value from one buffer to the other. Based on whether the
    // number of normalization functions is odd or even, the initial buffer is chosen so that the
    // final normalization leaves the normalized header value in norm_value.

    uint8_t* const norm_value = new uint8_t[buffer_length];
    uint8_t* const temp_space = new uint8_t[buffer_length];
    // cppcheck-suppress uninitdata
    uint8_t* const norm_start = (num_normalizers%2 == 0) ? norm_value : temp_space;
    uint8_t* working = norm_start;
    int32_t data_length = 0;
    const bool create_combined_raw = (count > 1);
    uint8_t* const combined_raw = (create_combined_raw) ? new uint8_t[buffer_length] : nullptr;
    uint8_t* working_raw = combined_raw;
    for (int j=0; j < num_matches; j++)
    {
        if (j >= 1)
        {
            *working++ = ',';
            if (create_combined_raw)
                *working_raw++ = ',';
            data_length++;
            while (header_name_id[++curr_match] != head_id);
        }
        const int32_t growth = derive_header_content(header_value[curr_match].start(),
            header_value[curr_match].length(), working, alert_ws, infractions, events);
        working += growth;
        data_length += growth;

        if (create_combined_raw)
        {
            memcpy(working_raw, header_value[curr_match].start(),
                header_value[curr_match].length());
            working_raw += header_value[curr_match].length();
        }
    }

    if (create_combined_raw)
    {
        assert((working_raw - combined_raw) == buffer_length);
        comma_separated_raw.set(buffer_length, combined_raw, true);
    }

    // Many fields names can appear more than once but some should not. If an event or infraction
    // is defined we will check as part of normalization. A comma-separated header value is
    // equivalent to a repeated header name. This is JIT code and we will not check for repeated
    // headers unless someone asks for that header.
    if ((repeat_event != EVENT__NONE) || (repeat_inf != INF__NONE))
    {
        if (count >= 2)
        {
            *infractions += repeat_inf;
            events->create_event(repeat_event);
        }
        else
        {
            for (int k=0; k < data_length; k++)
            {
                if (norm_start[k] == ',')
                {
                    *infractions += repeat_inf;
                    events->create_event(repeat_event);
                    break;
                }
            }
        }
    }

    for (int i=0; i < num_normalizers; i++)
    {
        if (i%2 != num_normalizers%2)
        {
            data_length = normalizer[i](temp_space, data_length, norm_value, infractions, events);
        }
        else
        {
            data_length = normalizer[i](norm_value, data_length, temp_space, infractions, events);
        }
    }
    delete[] temp_space;
    result_field.set(data_length, norm_value, true);
}

//-------------------------------------------------------------------------
// End - HeaderNormalizer class
//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
// NormalizedHeader class
//-------------------------------------------------------------------------
const Field& NormalizedHeader::get_norm(HttpInfractions* infractions, HttpEventGen* events,
    const HttpEnums::HeaderId header_name_id[], const Field header_value[],
    const int32_t num_headers)
{
    if (norm.length() == STAT_NOT_COMPUTE)
    {
        header_norms[id]->normalize(id, count, infractions, events,
            header_name_id, header_value, num_headers, norm, comma_separated_raw);
    }

    return norm;
}

const Field& NormalizedHeader::get_comma_separated_raw(const HttpMsgHeadShared& msg_head,
    HttpInfractions* infractions, HttpEventGen* events, const HttpEnums::HeaderId header_name_id[],
    const Field header_value[], const int32_t num_headers)
{
    if (count == 1)
        return msg_head.get_header_value_raw(id);

    if (comma_separated_raw.length() == STAT_NOT_COMPUTE)
    {
        header_norms[id]->normalize(id, count, infractions, events,
            header_name_id, header_value, num_headers, norm, comma_separated_raw);
    }

    return comma_separated_raw;
}
