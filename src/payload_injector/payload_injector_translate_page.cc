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

// payload_injector_translate_page.cc author Maya Dagon <mdagon@cisco.com>

// Translates HTTP 1.1 block/redirect page to HTTP2.
// 1. Headers are separated by \r\n or \n
// 2. Headers end with \r\n or \n
// 3. Must have headers and body
// 4. Translated header length <= 2000
// 5. Supported: HTTP/1.1 200, HTTP/1.1 403, HTTP/1.1 307, Content-Type: ,
//               Set-Cookie: , Location:
// 6. Connection: close, Content-Length: are removed during translation

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "payload_injector.h"

#include "service_inspectors/http2_inspect/http2_enum.h"
#include "utils/util.h"

using namespace Http2Enums;

static const char status_403[] = "HTTP/1.1 403";
static uint8_t status_403_h2[] = { 0, 7, ':', 's', 't', 'a', 't', 'u', 's', 3, '4', '0', '3' };
static const char status_307[] = "HTTP/1.1 307";
static uint8_t status_307_h2[] = { 0, 7, ':', 's', 't', 'a', 't', 'u', 's', 3, '3', '0', '7' };
static const char status_200[] = "HTTP/1.1 200";
static uint8_t status_200_h2[] =  { 0x88 };
static const char connection[] = "Connection: close";
static const char content_length[] = "Content-Length: ";
static const char content_type[] = "Content-Type: ";
static const char cookie[] = "Set-Cookie: ";
static const char location[] = "Location: ";

static const uint32_t max_hdr_size = 2000;

// Empty settings frame
static const uint8_t empty_settings_frame[] = { 0, 0, 0, FT_SETTINGS, 0, 0, 0, 0, 0 };

// Goaway frame header
static const uint8_t goaway_frame_len = 8; // 4 bytes stream id + 4 bytes error code
static const uint8_t goaway_frame_header[] = { 0, 0, goaway_frame_len, FT_GOAWAY, 0, 0, 0, 0, 0};

static InjectionReturnStatus write_translation(uint8_t*& out, uint32_t& out_free_space,
    const uint8_t* translation, uint32_t size)
{
    if (out_free_space < size)
    {
#ifndef UNIT_TEST
        assert(false);  // increase max_hdr_size
#endif
        return ERR_TRANSLATED_HDRS_SIZE;
    }

    memcpy(out, translation, size);
    out += size;
    out_free_space -= size;

    return INJECTION_SUCCESS;
}

#ifndef UNIT_TEST
static
#endif
InjectionReturnStatus write_7_bit_prefix_int(uint32_t val, uint8_t*& out, uint32_t& out_free_space)
{
    uint8_t write_val;
    if (val < ((1<<7) - 1))
    {
        write_val = val;
        return write_translation(out, out_free_space, &write_val, 1);
    }

    write_val = (1<<7) - 1;
    InjectionReturnStatus status =  write_translation(out, out_free_space, &write_val, 1);
    if (status != INJECTION_SUCCESS)
        return status;
    val -= write_val;

    while (val >= 128)
    {
        write_val = val % 128 + 128;
        status =  write_translation(out, out_free_space, &write_val, 1);
        if (status != INJECTION_SUCCESS)
            return status;
        val = val/128;
    }
    write_val = val;
    status =  write_translation(out, out_free_space, &write_val, 1);
    return status;
}

// Write literal header field
static InjectionReturnStatus write_indexed(const uint8_t* hdr, uint32_t len, uint8_t*& out,
    uint32_t& out_free_space, const uint8_t* ind, uint8_t ind_size)
{
    const uint8_t* sep = (const uint8_t*)memchr(hdr,':',len);
    assert(sep != nullptr);
    const uint32_t skip_len = strlen(": ");
    assert((sep - hdr) >= skip_len);
    const uint32_t val_len = len - (sep - hdr) - skip_len;

    if (val_len == 0)
        return ERR_PAGE_TRANSLATION;

    InjectionReturnStatus status = write_translation(out, out_free_space, ind, ind_size);
    if (status != INJECTION_SUCCESS)
        return status;

    status = write_7_bit_prefix_int(val_len, out, out_free_space);
    if (status != INJECTION_SUCCESS)
        return status;

    status = write_translation(out, out_free_space, sep + skip_len, val_len);

    return status;
}

static InjectionReturnStatus translate_hdr_field(const uint8_t* hdr, uint32_t len, uint8_t*& out,
    uint32_t& out_free_space)
{
    if (len > strlen(status_403) && memcmp(hdr, status_403, strlen(status_403)) == 0)
    {
        return write_translation(out, out_free_space,status_403_h2, sizeof(status_403_h2));
    }
    else if (len > strlen(status_307) && memcmp(hdr, status_307, strlen(status_307)) == 0)
    {
        return write_translation(out, out_free_space, status_307_h2, sizeof(status_307_h2));
    }
    else if (len > strlen(status_200) && memcmp(hdr, status_200, strlen(status_200)) == 0)
    {
        return write_translation(out, out_free_space, status_200_h2, sizeof(status_200_h2));
    }
    else if (len == strlen(connection) && memcmp(hdr, connection, strlen(connection))==0)
    {
        return INJECTION_SUCCESS;
    }
    // The following use literal header field without indexing.
    // The header field name index to the static table is represented using 4-bit prefix.
    else if (len > strlen(content_length) && memcmp(hdr, content_length, strlen(content_length))==
        0)
    {
        return INJECTION_SUCCESS;
    }
    else if (len > strlen(content_type) && memcmp(hdr, content_type, strlen(content_type))==0)
    {
        const uint8_t ind_rep[] = { 0xf, 0x10 }; // 0000 + 31 in 4 bit prefix
        return write_indexed(hdr, len, out, out_free_space, ind_rep, sizeof(ind_rep));
    }
    else if (len > strlen(cookie) && memcmp(hdr, cookie, strlen(cookie))==0)
    {
        const uint8_t ind_rep[] = { 0xf, 0x28 }; // 0000 + 55 in 4 bit prefix
        return write_indexed(hdr, len, out, out_free_space, ind_rep, sizeof(ind_rep));
    }
    else if (len > strlen(location) && memcmp(hdr, location, strlen(location))==0)
    {
        const uint8_t ind_rep[] = { 0xf, 0x1f }; // 0000 + 46 in 4 bit prefix
        return write_indexed(hdr, len, out, out_free_space, ind_rep, sizeof(ind_rep));
    }
    else
        return ERR_PAGE_TRANSLATION;
}

static InjectionReturnStatus get_http2_hdr(const uint8_t* http_page, uint32_t len,
    uint8_t* http2_hdr, uint32_t& hdr_len, uint32_t& body_offset)
{
    InjectionReturnStatus status = ERR_PAGE_TRANSLATION;
    body_offset = 0;

    uint32_t hdr_free_space = max_hdr_size;
    const uint8_t* page_cur = http_page;
    uint8_t* hdr_cur = http2_hdr;
    while ((page_cur - http_page) < len)
    {
        const uint8_t* newline = (const uint8_t*)memchr(page_cur, '\n', len - (page_cur -
            http_page));
        if (newline != nullptr)
        {
            // FIXIT-E only \r\n should be supported
            if (newline == page_cur || (newline == page_cur + 1 && *page_cur == '\r'))
            {
                // reached end of headers
                if ((newline + 1 - http_page) < len)
                    body_offset = newline + 1 - http_page;
                break;
            }
            if (*(newline - 1) == '\r')
                status = translate_hdr_field(page_cur, newline - page_cur - 1, hdr_cur,
                    hdr_free_space);
            else
                status = translate_hdr_field(page_cur, newline - page_cur, hdr_cur,
                    hdr_free_space);
            if (status != INJECTION_SUCCESS)
                break;
            page_cur = newline + 1;
        }
        else
            break;
    }

    if (status != INJECTION_SUCCESS)
        return status;

    if (body_offset == 0)
        return ERR_PAGE_TRANSLATION;

    hdr_len = hdr_cur - http2_hdr;

    return INJECTION_SUCCESS;
}

static void write_3_bytes_of_int(uint8_t* out, uint32_t val)
{
#ifdef WORDS_BIGENDIAN
    out[2] = (val & (0xff000000)) >> 24;
    out[1] = (val & (0xff0000)) >> 16;
    out[0] = (val & (0xff00)) >> 8;
#else
    out[2] = val & 0xff;
    out[1] = (val & (0xff00)) >> 8;
    out[0] = (val & (0xff0000)) >> 16;
#endif
}

static void write_frame_hdr(uint8_t*& out, uint32_t len, uint8_t type, uint8_t flags, uint32_t
    stream_id)
{
    write_3_bytes_of_int(out, len);
    out[3] = type;
    out[4] = flags;
    stream_id = htonl(stream_id);
    memcpy(out+5, &stream_id, 4);
    out += FRAME_HEADER_LENGTH;
}

static void write_goaway_frame(uint8_t*& out, uint32_t stream_id)
{
    memcpy(out, goaway_frame_header, FRAME_HEADER_LENGTH);
    out += FRAME_HEADER_LENGTH;
    stream_id = htonl(stream_id);
    memcpy(out, &stream_id, 4);
    const uint32_t error_code = 0;
    memcpy(out+4, &error_code, 4);
    out += goaway_frame_len;
}

InjectionReturnStatus PayloadInjector::get_http2_payload(InjectionControl control,
    uint8_t*& http2_payload, uint32_t& payload_len, bool send_settings)
{
    if (control.http_page == nullptr || control.http_page_len == 0)
        return ERR_PAGE_TRANSLATION;

    uint8_t http2_hdr[max_hdr_size];
    uint32_t hdr_len, body_offset;
    InjectionReturnStatus status = get_http2_hdr(control.http_page, control.http_page_len,
        http2_hdr, hdr_len, body_offset);

    if (status != INJECTION_SUCCESS)
        return status;

    uint32_t body_len = control.http_page_len - body_offset;
    uint32_t num_data_frames = body_len / (1<<14);
    if (body_len % (1<<14) != 0)
        num_data_frames++;
    payload_len = FRAME_HEADER_LENGTH*(num_data_frames + 1) + hdr_len + body_len; // block page
    payload_len += FRAME_HEADER_LENGTH + goaway_frame_len; // goaway frame
    if (send_settings)
        payload_len += sizeof(empty_settings_frame);
    http2_payload = (uint8_t*)snort_alloc(payload_len);

    uint8_t* http2_payload_cur = http2_payload;
    if (send_settings)
    {
        memcpy(http2_payload_cur, empty_settings_frame, sizeof(empty_settings_frame));
        http2_payload_cur += sizeof(empty_settings_frame);
    }
    write_frame_hdr(http2_payload_cur, hdr_len, FT_HEADERS, FLAG_END_HEADERS, control.stream_id);
    memcpy(http2_payload_cur, http2_hdr, hdr_len);
    http2_payload_cur += hdr_len;
    const uint8_t* http_body_cur = control.http_page + body_offset;
    while (body_len)
    {
        const uint32_t cur_len = (body_len > 1<<14) ? 1<<14 : body_len;
        body_len -= cur_len;
        const uint8_t flags = (body_len == 0) ? FLAG_END_STREAM : 0;
        write_frame_hdr(http2_payload_cur, cur_len, FT_DATA, flags, control.stream_id);
        memcpy(http2_payload_cur, http_body_cur, cur_len);
        http2_payload_cur += cur_len;
        http_body_cur += cur_len;
    }
    write_goaway_frame(http2_payload_cur, control.stream_id);
    assert((http2_payload_cur - http2_payload) == payload_len);
    return INJECTION_SUCCESS;
}

