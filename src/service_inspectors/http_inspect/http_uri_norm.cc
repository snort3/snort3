//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// http_uri_norm.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_uri_norm.h"

#include <sstream>

#include "log/messages.h"

using namespace HttpEnums;

void UriNormalizer::normalize(const Field& input, Field& result, bool do_path, uint8_t* buffer,
    const HttpParaList::UriParam& uri_param, HttpInfractions* infractions, HttpEventGen* events)
{
    // Normalize percent encodings and similar escape sequences
    int32_t data_length = norm_char_clean(input, buffer, uri_param, infractions, events);

    detect_bad_char(Field(data_length, buffer), uri_param, infractions, events);

    norm_substitute(buffer, data_length, uri_param, infractions, events);

    // Normalize path directory traversals
    if (do_path && uri_param.simplify_path)
    {
        data_length = norm_path_clean(buffer, data_length, infractions, events);
    }

    result.set(data_length, buffer);
}

bool UriNormalizer::need_norm(const Field& uri_component, bool do_path,
    const HttpParaList::UriParam& uri_param, HttpInfractions* infractions, HttpEventGen* events)
{
    bool need_it;
    if (do_path && uri_param.simplify_path)
        need_it = need_norm_path(uri_component, uri_param);
    else
        need_it = need_norm_no_path(uri_component, uri_param);

    if (!need_it)
    {
        // Since we are not going to normalize we need to check for bad characters now
        detect_bad_char(uri_component, uri_param, infractions, events);
    }

    return need_it;
}

bool UriNormalizer::need_norm_no_path(const Field& uri_component,
    const HttpParaList::UriParam& uri_param)
{
    for (int32_t k = 0; k < uri_component.length(); k++)
    {
        if ((uri_param.uri_char[uri_component.start()[k]] == CHAR_PERCENT) ||
            (uri_param.uri_char[uri_component.start()[k]] == CHAR_SUBSTIT))
            return true;
    }
    return false;
}

bool UriNormalizer::need_norm_path(const Field& uri_component,
    const HttpParaList::UriParam& uri_param)
{
    const int32_t length = uri_component.length();
    const uint8_t* const buf = uri_component.start();
    for (int32_t k = 0; k < length; k++)
    {
        switch (uri_param.uri_char[buf[k]])
        {
        case CHAR_NORMAL:
        case CHAR_EIGHTBIT:
            continue;
        case CHAR_PERCENT:
        case CHAR_SUBSTIT:
            return true;
        case CHAR_PATH:
            if (buf[k] == '/')
            {
                // slash is safe if not preceded by another slash
                if ((k == 0) || (buf[k-1] != '/'))
                    continue;
                return true;
            }
            else
            {
                // period is safe if not preceded or followed by another path character
                if (((k == 0) || (uri_param.uri_char[buf[k-1]] != CHAR_PATH))          &&
                    ((k == length-1) || (uri_param.uri_char[buf[k+1]] != CHAR_PATH)))
                    continue;
                return true;
            }
        }
    }
    return false;
}

int32_t UriNormalizer::norm_char_clean(const Field& input, uint8_t* out_buf,
    const HttpParaList::UriParam& uri_param, HttpInfractions* infractions, HttpEventGen* events)
{
    bool utf8_needed = false;
    bool double_decoding_needed = false;
    std::vector<bool> percent_encoded(input.length(), false);
    int32_t length = norm_percent_processing(input, out_buf, uri_param, utf8_needed,
        percent_encoded, double_decoding_needed, infractions, events);
    if (uri_param.utf8 && utf8_needed)
    {
        length = norm_utf8_processing(Field(length, out_buf), out_buf, uri_param, percent_encoded,
            double_decoding_needed, infractions, events);
    }
    if (uri_param.iis_double_decode && double_decoding_needed)
    {
        length = norm_double_decode(Field(length, out_buf), out_buf, uri_param, infractions,
            events);
    }
    return length;
}

int32_t UriNormalizer::norm_percent_processing(const Field& input, uint8_t* out_buf,
    const HttpParaList::UriParam& uri_param, bool& utf8_needed,
    std::vector<bool>& percent_encoded, bool& double_decoding_needed,
    HttpInfractions* infractions, HttpEventGen* events)
{
    int32_t length = 0;
    for (int32_t k = 0; k < input.length(); k++)
    {
        switch (uri_param.uri_char[input.start()[k]])
        {
        case CHAR_EIGHTBIT:
            if (uri_param.utf8_bare_byte &&
               (((input.start()[k] & 0xE0) == 0xC0) || ((input.start()[k] & 0xF0) == 0xE0)))
                utf8_needed = true;
            // Fall through
        case CHAR_NORMAL:
        case CHAR_PATH:
        case CHAR_SUBSTIT:
            out_buf[length++] = input.start()[k];
            break;
        case CHAR_PERCENT:
            if (is_percent_encoding(input, k))
            {
                // %hh => hex value
                const uint8_t hex_val = extract_percent_encoding(input, k);
                percent_encoded[length] = true;
                // Test for possible start of two-byte (110xxxxx) or three-byte (1110xxxx) UTF-8
                if (((hex_val & 0xE0) == 0xC0) || ((hex_val & 0xF0) == 0xE0))
                    utf8_needed = true;
                if (hex_val == '%')
                    double_decoding_needed = true;
                out_buf[length++] = hex_val;
                k += 2;
            }
            else if ((k+1 < input.length()) && (input.start()[k+1] == '%'))
            {
                // %% => %
                double_decoding_needed = true;
                out_buf[length++] = '%';
                k += 1;
            }
            else if (uri_param.percent_u && is_u_encoding(input, k))
            {
                // %u encoding, this is nonstandard and likely to be malicious
                *infractions += INF_URI_U_ENCODE;
                events->create_event(EVENT_U_ENCODE);
                percent_encoded[length] = true;
                const uint8_t byte_val = reduce_to_eight_bits(extract_u_encoding(input, k),
                    uri_param, infractions, events);
                if (((byte_val & 0xE0) == 0xC0) || ((byte_val & 0xF0) == 0xE0))
                    utf8_needed = true;
                if (byte_val == '%')
                    double_decoding_needed = true;
                out_buf[length++] = byte_val;
                k += 5;
            }
            else
            {
                // don't recognize, pass it through
                *infractions += INF_URI_UNKNOWN_PERCENT;
                events->create_event(EVENT_UNKNOWN_PERCENT);
                double_decoding_needed = true;
                out_buf[length++] = '%';
            }

            // The result of percent decoding should not be an "unreserved" character. That's a
            // strong clue someone is hiding something.
            if (uri_param.unreserved_char[out_buf[length-1]])
            {
                *infractions += INF_URI_PERCENT_UNRESERVED;
                events->create_event(EVENT_ASCII);
            }
            break;
        }
    }
    return length;
}

int32_t UriNormalizer::norm_utf8_processing(const Field& input, uint8_t* out_buf,
    const HttpParaList::UriParam& uri_param, const std::vector<bool>& percent_encoded,
    bool& double_decoding_needed, HttpInfractions* infractions, HttpEventGen* events)
{
    int32_t length = 0;
    for (int32_t k=0; k < input.length(); k++)
    {
        if (percent_encoded[k] || uri_param.utf8_bare_byte)
        {
            // two-byte UTF-8: 110xxxxx 10xxxxxx
            if (((input.start()[k] & 0xE0) == 0xC0) &&
                (k+1 < input.length()) &&
                (percent_encoded[k+1] || uri_param.utf8_bare_byte) &&
                ((input.start()[k+1] & 0xC0) == 0x80))
            {
                *infractions += INF_URI_PERCENT_UTF8_2B;
                events->create_event(EVENT_UTF_8);
                if (!percent_encoded[k] || !percent_encoded[k+1])
                {
                    *infractions += INF_BARE_BYTE;
                    events->create_event(EVENT_BARE_BYTE);
                }
                const uint16_t utf8_val = ((input.start()[k] & 0x1F) << 6) +
                                           (input.start()[k+1] & 0x3F);
                const uint8_t val8 = reduce_to_eight_bits(utf8_val, uri_param, infractions,
                    events);
                if (val8 == '%')
                    double_decoding_needed = true;
                out_buf[length++] = val8;
                k += 1;
            }
            // three-byte UTF-8: 1110xxxx 10xxxxxx 10xxxxxx
            else if (((input.start()[k] & 0xF0) == 0xE0) &&
                (k+2 < input.length()) &&
                (percent_encoded[k+1] || uri_param.utf8_bare_byte) &&
                ((input.start()[k+1] & 0xC0) == 0x80) &&
                (percent_encoded[k+2] || uri_param.utf8_bare_byte) &&
                ((input.start()[k+2] & 0xC0) == 0x80))
            {
                *infractions += INF_URI_PERCENT_UTF8_3B;
                events->create_event(EVENT_UTF_8);
                if (!percent_encoded[k] || !percent_encoded[k+1] || !percent_encoded[k+2])
                {
                    *infractions += INF_BARE_BYTE;
                    events->create_event(EVENT_BARE_BYTE);
                }
                const uint16_t utf8_val = ((input.start()[k] & 0x0F) << 12) +
                                          ((input.start()[k+1] & 0x3F) << 6) +
                                           (input.start()[k+2] & 0x3F);
                const uint8_t val8 = reduce_to_eight_bits(utf8_val, uri_param, infractions,
                    events);
                if (val8 == '%')
                    double_decoding_needed = true;
                out_buf[length++] = val8;
                k += 2;
            }
            else
                out_buf[length++] = input.start()[k];
        }
        else
            out_buf[length++] = input.start()[k];
    }
    return length;
}

int32_t UriNormalizer::norm_double_decode(const Field& input, uint8_t* out_buf,
    const HttpParaList::UriParam& uri_param, HttpInfractions* infractions,
    HttpEventGen* events)
{
    // Double decoding is limited to %hh and %u encoding cases
    int32_t length = 0;
    for (int32_t k = 0; k < input.length(); k++)
    {
        if (input.start()[k] != '%')
            out_buf[length++] = input.start()[k];
        else
        {
            if (is_percent_encoding(input, k))
            {
                *infractions += INF_URI_DOUBLE_DECODE;
                events->create_event(EVENT_DOUBLE_DECODE);
                out_buf[length++] = extract_percent_encoding(input, k);
                k += 2;
            }
            else if (uri_param.percent_u && is_u_encoding(input, k))
            {
                *infractions += INF_URI_DOUBLE_DECODE;
                events->create_event(EVENT_DOUBLE_DECODE);
                *infractions += INF_URI_U_ENCODE;
                events->create_event(EVENT_U_ENCODE);
                out_buf[length++] = reduce_to_eight_bits(extract_u_encoding(input, k), uri_param,
                    infractions, events);
                k += 5;
            }
            else
            {
                out_buf[length++] = '%';
            }
        }
    }
    return length;
}

uint8_t UriNormalizer::reduce_to_eight_bits(uint16_t value,
    const HttpParaList::UriParam& uri_param, HttpInfractions* infractions, HttpEventGen* events)
{
    // FIXIT-M are values <= 0xFF subject to the unicode map?
    if (value <= 0xFF)
        return value;
    if (!uri_param.iis_unicode)
        return 0xFF;
    if (uri_param.unicode_map[value] != 0xFF)
    {
        *infractions += INF_CODE_POINT_IN_URI;
        events->create_event(EVENT_CODE_POINT_IN_URI);
    }
    return uri_param.unicode_map[value];
}

void UriNormalizer::detect_bad_char(const Field& uri_component,
    const HttpParaList::UriParam& uri_param, HttpInfractions* infractions, HttpEventGen* events)
{
    // If the bad character detection feature is not configured we quit
    if (uri_param.bad_characters.count() == 0)
        return;

    for (int32_t k = 0; k < uri_component.length(); k++)
    {
        if (uri_param.bad_characters[uri_component.start()[k]])
        {
            *infractions += INF_URI_BAD_CHAR;
            events->create_event(EVENT_NON_RFC_CHAR);
            return;
        }
    }
}

// Replace backslash with slash and plus with space
void UriNormalizer::norm_substitute(uint8_t* buf, int32_t length,
    const HttpParaList::UriParam& uri_param, HttpInfractions* infractions, HttpEventGen* events)
{
    if (uri_param.backslash_to_slash)
    {
        for (int32_t k = 0; k < length; k++)
        {
            if (buf[k] == '\\')
            {
                buf[k] = '/';
                *infractions += INF_BACKSLASH_IN_URI;
                events->create_event(EVENT_BACKSLASH_IN_URI);
            }
        }
    }
    if (uri_param.plus_to_space)
    {
        for (int32_t k = 0; k < length; k++)
        {
            if (buf[k] == '+')
            {
                buf[k] = ' ';
            }
        }
    }
}

// Caution: worst case output length is one greater than input length
int32_t UriNormalizer::norm_path_clean(uint8_t* buf, const int32_t in_length,
    HttpInfractions* infractions, HttpEventGen* events)
{
    // This is supposed to be the path portion of a URI. Read HttpUri::parse_uri() for an
    // explanation.
    assert(buf[0] == '/');

    int32_t length = 0;
    // It simplifies the code that handles /./ and /../ to pretend there is an extra '/' after the
    // buffer. Avoids making a special case of URIs that end in . or .. That is why the loop steps
    // off the end of the input buffer by saying <= instead of <.
    for (int32_t k = 0; k <= in_length; k++)
    {
        // Pass through all non-slash characters and also the leading slash
        if (((k < in_length) && (buf[k] != '/')) || (k == 0))
        {
            buf[length++] = buf[k];
        }
        // Ignore this slash if it directly follows another slash
        else if ((k < in_length) && (length >= 1) && (buf[length-1] == '/'))
        {
            *infractions += INF_URI_MULTISLASH;
            events->create_event(EVENT_MULTI_SLASH);
        }
        // This slash is the end of a /./ pattern, ignore this slash and remove the period from the
        // output
        else if ((length >= 2) && (buf[length-1] == '.') && (buf[length-2] == '/'))
        {
            *infractions += INF_URI_SLASH_DOT;
            events->create_event(EVENT_SELF_DIR_TRAV);
            length -= 1;
        }
        // This slash is the end of a /../ pattern, normalization depends on whether there is a
        // previous directory that we can remove
        else if ((length >= 3) && (buf[length-1] == '.') && (buf[length-2] == '.') &&
            (buf[length-3] == '/'))
        {
            *infractions += INF_URI_SLASH_DOT_DOT;
            events->create_event(EVENT_DIR_TRAV);
            // Traversing above the root of the absolute path. A path of the form
            // /../../../foo/bar/whatever cannot be further normalized. Instead of taking away a
            // directory we leave the .. and write out the new slash. This code can write out the
            // pretend slash after the end of the buffer. That is intentional so that the normal
            // form of "/../../../.." is "/../../../../"
            if ( (length == 3) ||
                ((length >= 6) && (buf[length-4] == '.') && (buf[length-5] == '.') &&
                (buf[length-6] == '/')))
            {
                *infractions += INF_URI_ROOT_TRAV;
                events->create_event(EVENT_WEBROOT_DIR);
                buf[length++] = '/';
            }
            // Remove the previous directory from the output. "/foo/bar/../" becomes "/foo/"
            else
            {
                for (length -= 3; buf[length-1] != '/'; length--);
            }
        }
        // Pass through an ordinary slash
        else if (k < in_length)
        {
            buf[length++] = '/';
        }
    }
    return length;
}

// Provide traditional URI-style normalization for buffers that usually are not URIs
void UriNormalizer::classic_normalize(const Field& input, Field& result,
    const HttpParaList::UriParam& uri_param)
{
    // The requirements for generating events related to these normalizations are unclear. It
    // definitely doesn't seem right to generate standard URI events. For now we won't generate
    // any events at all because these buffers may well not be URIs so regardless of what we find
    // it is "normal". Similarly we don't have any reason to track any infractions.

    // We want to reuse all the URI-normalization functions without complicating their event and
    // infraction logic with legacy problems. The following centralizes all the messiness here so
    // that we can conveniently modify it as requirements are better understood.

    HttpInfractions unused;
    HttpDummyEventGen dummy_ev;

    uint8_t* const buffer = new uint8_t[input.length() + URI_NORM_EXPANSION];

    // Normalize character escape sequences
    int32_t data_length = norm_char_clean(input, buffer, uri_param, &unused, &dummy_ev);

    if (uri_param.simplify_path)
    {
        // Normalize path directory traversals
        // Find the leading slash if there is one
        uint8_t* first_slash = (uint8_t*)memchr(buffer, '/', data_length);
        if (first_slash != nullptr)
        {
            const int32_t uri_offset = first_slash - buffer;
            norm_substitute(buffer + uri_offset, data_length - uri_offset, uri_param, &unused,
                &dummy_ev);
            data_length = uri_offset +
                norm_path_clean(buffer + uri_offset, data_length - uri_offset, &unused, &dummy_ev);
        }
    }

    result.set(data_length, buffer, true);
}

bool UriNormalizer::classic_need_norm(const Field& uri_component, bool do_path,
    const HttpParaList::UriParam& uri_param)
{
    HttpInfractions unused;
    HttpDummyEventGen dummy_ev;

    return need_norm(uri_component, do_path, uri_param, &unused, &dummy_ev);
}

void UriNormalizer::load_default_unicode_map(uint8_t map[65536])
{
    memset(map, 0xFF, 65536);

    // Default unicode map is just a single string of tokens of the form
    // HHHH:HH (HHHH = unicode, HH = ascii char)
// __STRDUMP_DISABLE__
    std::stringstream ss(
"0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 "
"010c:43 010d:63 010e:44 010f:64 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 "
"0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 "
"0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 "
"0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c "
"0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f "
"0151:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 "
"015f:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 "
"016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0179:5a "
"017b:5a 017c:7a 0180:62 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 "
"01b6:7a 01c0:7c 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 "
"01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 "
"01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 "
"02c4:5e 02c8:27 02cb:60 02cd:5f 0300:60 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 037e:3b 0393:47 "
"0398:54 03a3:53 03a6:46 03a9:4f 03b1:61 03b4:64 03b5:65 03c0:70 03c3:73 03c4:74 03c6:66 04bb:68 "
"0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2017:3d "
"2032:27 2035:60 2044:2f 2074:34 2075:35 2076:36 2077:37 2078:38 207f:6e 2080:30 2081:31 2082:32 "
"2083:33 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 20a7:50 2102:43 2107:45 210a:67 210b:48 "
"210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:50 2119:50 211a:51 211b:52 "
"211c:52 211d:52 2124:5a 2128:5a 212a:4b 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d "
"2134:6f 2212:2d 2215:2f 2216:5c 2217:2a 221a:76 221e:38 2223:7c 2229:6e 2236:3a 223c:7e 2261:3d "
"2264:3d 2265:3d 2303:5e 2320:28 2321:29 2329:3c 232a:3e 2500:2d 250c:2b 2510:2b 2514:2b 2518:2b "
"251c:2b 252c:2d 2534:2d 253c:2b 2550:2d 2552:2b 2553:2b 2554:2b 2555:2b 2556:2b 2557:2b 2558:2b "
"2559:2b 255a:2b 255b:2b 255c:2b 255d:2b 2564:2d 2565:2d 2566:2d 2567:2d 2568:2d 2569:2d 256a:2b "
"256b:2b 256c:2b 2584:5f 2758:7c 3000:20 3008:3c 3009:3e 301a:5b 301b:5d ff01:21 ff02:22 ff03:23 "
"ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f "
"ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b "
"ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 "
"ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 "
"ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 "
"ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c "
"ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 "
"ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e");
// __STRDUMP_ENABLE__

    std::string token;

    while (ss >> token)
    {
        const uint16_t ucode = strtol(token.c_str(), nullptr, 16);
        map[ucode] = strtol(token.c_str()+5, nullptr, 16);
    }
}

bool UriNormalizer::advance_to_code_page(FILE* file, int page_to_use)
{
    const char* WHITE_SPACE = " \t\n\r";
    const int MAX_BUFFER = 7;

    // Proceed line-by-line through the file until we find the desired code page number
    char buffer[MAX_BUFFER];
    while (fgets(buffer, MAX_BUFFER, file) != nullptr)
    {
        // Skip past the end of the line
        if (buffer[strlen(buffer)-1] != '\n')
        {
            int skip_char;
            while (((skip_char = fgetc(file)) != EOF) && (skip_char != '\n'));
        }

        // Code page number will always be first token on its line
        char* unused;
        const char* token = strtok_r(buffer, WHITE_SPACE, &unused);

        // Skip empty lines, comments, and lines of code points
        if ((token == nullptr) || (token[0] == '#') || strchr(token, ':'))
            continue;

        // We now have a code page number
        char* end;
        const int latest_page = strtol(token, &end, 10);
        if (*end != '\0')
            continue;

        if (latest_page == page_to_use)
        {
            // The next line in the file will be the desired code page
            return true;
        }
    }
    // The requested code page is not in the file
    return false;
}

bool UriNormalizer::map_code_points(FILE* file, uint8_t* map)
{
    // FIXIT-L file read error in middle of code points not recognized as error
    uint8_t buffer[8];
    for (bool first = true; true; first = false)
    {
        // Error if list of code points ends before it begins
        if ((fgets((char*)buffer, 8, file) == nullptr) || (buffer[0] == '\n'))
            return !first;

        // expect HHHH:HH format
        if ((strlen((char*)buffer) != 7) ||
            (as_hex[buffer[0]] == -1)    ||
            (as_hex[buffer[1]] == -1)    ||
            (as_hex[buffer[2]] == -1)    ||
            (as_hex[buffer[3]] == -1)    ||
            (buffer[4] != ':')           ||
            (as_hex[buffer[5]] == -1)    ||
            (as_hex[buffer[6]] == -1))
        {
            return false;
        }

        const uint16_t code_point = (as_hex[buffer[0]] << 12) |
                                    (as_hex[buffer[1]] << 8)  |
                                    (as_hex[buffer[2]] << 4)  |
                                     as_hex[buffer[3]];
        const uint8_t ascii_map = (as_hex[buffer[5]] << 4) | as_hex[buffer[6]];

        map[code_point] = ascii_map;

        // Skip following space
        const int next = fgetc(file);
        if ((next == EOF) || (next == '\n'))
            return true;
        if (next != ' ')
            return false;
    }
}

void UriNormalizer::load_unicode_map(uint8_t map[65536], const char* filename, int code_page)
{
    memset(map, 0xFF, 65536);

    FILE* file = fopen(filename, "r");
    if (file == nullptr)
    {
        snort::ParseError("Cannot open unicode map file %s", filename);
        return;
    }

    // Advance file to the desired code page
    if (!advance_to_code_page(file, code_page))
    {
        snort::ParseError("Did not find code page %d in unicode map file %s", code_page, filename);
        fclose(file);
        return;
    }

    if (!map_code_points(file, map))
    {
        snort::ParseError("Error while reading code page %d in unicode map file %s", code_page, filename);
        fclose(file);
        return;
    }

    fclose(file);
}

