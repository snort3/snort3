//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
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

/* Some UTF-{16,32}{le,be} normalization functions */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util_utf.h"

#include <cassert>
#include <cstring>

#ifdef HAVE_ICONV
#include <iconv.h>
#endif

#define DSTATE_FIRST 0
#define DSTATE_SECOND 1
#define DSTATE_THIRD 2
#define DSTATE_FOURTH 3

using namespace snort;

UtfDecodeSession::UtfDecodeSession()
{
    init_decode_utf_state();
}

/* init a new decode_utf_state_t */
void UtfDecodeSession::init_decode_utf_state()
{
    dstate.state = DSTATE_FIRST;
    dstate.charset = CHARSET_DEFAULT;
}

/* setters & getters */
void UtfDecodeSession::set_decode_utf_state_charset(CharsetCode charset)
{
    dstate.state = DSTATE_FIRST;
    dstate.charset = charset;
}

CharsetCode UtfDecodeSession::get_decode_utf_state_charset()
{
    return dstate.charset;
}

bool UtfDecodeSession::is_utf_encoding_present()
{
    if ( get_decode_utf_state_charset() > CHARSET_IRRELEVANT )
        return true;
    else
        return false;
}

/* Decode UTF-16le from src to dst.
 *
 * src          => buffer containing utf-16le text
 * src_len      => length of src
 * dst          => buffer to write translated text
 * dst_len      => length allocated for dst
 * bytes_copied => store the # of bytes copied to dst
 *
 * returns: true or false
 */

bool UtfDecodeSession::DecodeUTF16LE(const uint8_t* src, unsigned int src_len, uint8_t* dst,
    unsigned int dst_len, int* bytes_copied)
{
    const uint8_t* src_index = src;
    uint8_t* dst_index = dst;
    bool result = true;

    while ((src_index < (src + src_len)) &&
        (dst_index < (dst + dst_len)))
    {
        /* Copy first byte, skip second, failing if second byte != 0 */
        switch (dstate.state)
        {
        case DSTATE_FIRST:
            *dst_index++ = *src_index++;
            dstate.state = DSTATE_SECOND;
            break;
        case DSTATE_SECOND:
            if (*src_index++ != 0)
                result = false;
            dstate.state = DSTATE_FIRST;
            break;
        default:
            assert(false);
        }
    }

    *bytes_copied = (int)(dst_index - dst);

    return result;
}

/* Decode UTF-16be from src to dst.
 *
 * src          => buffer containing utf-16le text
 * src_len      => length of src
 * dst          => buffer to write translated text
 * dst_len      => length allocated for dst
 * bytes_copied => store the # of bytes copied to dst
 *
 * returns: true or false
 */

bool UtfDecodeSession::DecodeUTF16BE(const uint8_t* src, unsigned int src_len, uint8_t* dst,
    unsigned int dst_len, int* bytes_copied)
{
    const uint8_t* src_index = src;
    uint8_t* dst_index = dst;
    bool result = true;

    while ((src_index < (src + src_len)) &&
        (dst_index < (dst + dst_len)))
    {
        /* Skip first byte, copy second. */
        switch (dstate.state)
        {
        case DSTATE_FIRST:
            if (*src_index++ != 0)
                result = false;
            dstate.state = DSTATE_SECOND;
            break;
        case DSTATE_SECOND:
            *dst_index++ = *src_index++;
            dstate.state = DSTATE_FIRST;
            break;
        default:
            assert(false);
        }
    }

    *bytes_copied = (int)(dst_index - dst);

    return result;
}

/* Decode UTF-32le from src to dst.
 *
 * src          => buffer containing utf-16le text
 * src_len      => length of src
 * dst          => buffer to write translated text
 * dst_len      => length allocated for dst
 * bytes_copied => store the # of bytes copied to dst
 *
 * returns: true or false
 */

bool UtfDecodeSession::DecodeUTF32LE(const uint8_t* src, unsigned int src_len, uint8_t* dst,
    unsigned int dst_len, int* bytes_copied)
{
    const uint8_t* src_index = src;
    uint8_t* dst_index = dst;
    bool result = true;

    while ((src_index < (src + src_len)) &&
        (dst_index < (dst + dst_len)))
    {
        /* Copy the first byte, then skip three. */
        switch (dstate.state)
        {
        case DSTATE_FIRST:
            *dst_index++ = *src_index++;
            dstate.state++;
            break;
        case DSTATE_SECOND:
        case DSTATE_THIRD:
        case DSTATE_FOURTH:
            if (*src_index++ != 0)
                result = false;
            if (dstate.state == DSTATE_FOURTH)
                dstate.state = DSTATE_FIRST;
            else
                dstate.state++;
            break;
        default:
            assert(false);
        }
    }

    *bytes_copied = (int)(dst_index - dst);

    return result;
}

/* Decode UTF-32be from src to dst.
 *
 * src          => buffer containing utf-16le text
 * src_len      => length of src
 * dst          => buffer to write translated text
 * dst_len      => length allocated for dst
 * bytes_copied => store the # of bytes copied to dst
 *
 * returns: true or false
 */

bool UtfDecodeSession::DecodeUTF32BE(const uint8_t* src, unsigned int src_len, uint8_t* dst,
    unsigned int dst_len, int* bytes_copied)
{
    const uint8_t* src_index = src;
    uint8_t* dst_index = dst;
    bool result = true;

    while ((src_index < (src + src_len)) &&
        (dst_index < (dst + dst_len)))
    {
        /* Skip 3 bytes, copy the fourth. */
        switch (dstate.state)
        {
        case DSTATE_FIRST:
        case DSTATE_SECOND:
        case DSTATE_THIRD:
            if (*src_index++ != 0)
                result = false;
            dstate.state++;
            break;
        case DSTATE_FOURTH:
            *dst_index++ = *src_index++;
            dstate.state = DSTATE_FIRST;
            break;
        default:
            assert(false);
        }
    }

    *bytes_copied = (int)(dst_index - dst);

    return result;
}

void UtfDecodeSession::determine_charset(const uint8_t** src, unsigned int* src_len)
{
    CharsetCode charset;
    if (dstate.charset == CHARSET_UNKNOWN)
    {
        /* Got a text content type but no charset.
         * Look for potential BOM (Byte Order Mark) */
        if (*src_len >= 4)
        {
            uint8_t size = 0;

            if (!memcmp(*src, "\x00\x00\xFE\xFF", 4))
            {
                charset = CHARSET_UTF32BE;
                size = 4;
            }
            else if (!memcmp(*src, "\xFF\xFE\x00\x00", 4))
            {
                charset = CHARSET_UTF32LE;
                size = 4;
            }
            else if (!memcmp(*src, "\xFE\xFF", 2))
            {
                charset = CHARSET_UTF16BE;
                size = 2;
            }
            else if (!memcmp(*src, "\xFF\xFE", 2))
            {
                charset = CHARSET_UTF16LE;
                size = 2;
            }
            //  BOM (Byte Order Mark) was missing. Try to guess the encoding.
            else if (((*src)[0] == '\0') && ((*src)[2] == '\0') && ((*src)[3] != '\0'))
            {
                if ((*src)[1] != '\0')
                    charset = CHARSET_UTF16BE;  // \0C\0C
                else
                    charset = CHARSET_UTF32BE;  // \0\0\0C
            }
            else if (((*src)[0] != '\0') && ((*src)[1] == '\0') && ((*src)[3] == '\0'))
            {
                if ((*src)[2] != '\0')
                    charset = CHARSET_UTF16LE;  // C\0C\0
                else
                    charset = CHARSET_UTF32LE;  // C\0\0\0
            }
            else
            {
                // NOTE: The UTF-8 BOM (Byte Order Mark) does not match the above cases, so we end
                // up here when parsing UTF-8. That works out for the moment because the first 128
                // characters of UTF-8 are identical to ASCII. We may want to handle other UTF-8
                // characters beyond 0x7f in the future.

                charset = CHARSET_DEFAULT; // ensure we don't try again
            }

            // FIXIT-M We are not currently handling the case where some characters are not ASCII
            // and some are ASCII. This is a problem because some UTF-16 characters have no NUL
            // bytes (so won't be identified as UTF-16.)

            // FIXIT-L We also do not handle multiple levels of encoding (where unicode becomes
            // %u0020 for example).

            *src += size;
            *src_len -= size;
        }
        else
        {
            charset = CHARSET_DEFAULT; // ensure we don't try again
        }
        set_decode_utf_state_charset(charset);
    }
}

/* Wrapper function for DecodeUTF{16,32}{LE,BE} */
bool UtfDecodeSession::decode_utf(
    const uint8_t* src, unsigned int src_len, uint8_t* dst, unsigned int dst_len,
    int* bytes_copied)
{
    *bytes_copied = 0;

    determine_charset(&src, &src_len);

    if (!src_len)
        return false;

    switch (dstate.charset)
    {
    case CHARSET_UTF16LE:
        return DecodeUTF16LE(src, src_len, dst, dst_len, bytes_copied);
    case CHARSET_UTF16BE:
        return DecodeUTF16BE(src, src_len, dst, dst_len, bytes_copied);
    case CHARSET_UTF32LE:
        return DecodeUTF32LE(src, src_len, dst, dst_len, bytes_copied);
    case CHARSET_UTF32BE:
        return DecodeUTF32BE(src, src_len, dst, dst_len, bytes_copied);
    default:
        break;
    }

    return true;
}

#ifdef HAVE_ICONV

char* UtfDecodeSession::convert_character_encoding(const char* to_code, const char* from_code,
    char* in_buf, char* out_buf, size_t in_bytes, size_t out_bytes, size_t* out_buf_length)
{
    iconv_t convert_encoding = iconv_open(to_code, from_code);
    if (convert_encoding == (iconv_t)-1)
        return nullptr;

    char* out = out_buf;
    size_t iconv_rval = iconv(convert_encoding, &in_buf, &in_bytes, &out, &out_bytes);
    if (iconv_rval == (size_t)-1)
    {
        iconv_close(convert_encoding);
        return nullptr;
    }

    *out = '\0';
    *out_buf_length = (out - out_buf);

    iconv_close(convert_encoding);
    return out_buf;
}

#else

char* UtfDecodeSession::convert_character_encoding(const char*, const char*,
    char*, char*, size_t, size_t, size_t*)
{
    return nullptr;
}

#endif

