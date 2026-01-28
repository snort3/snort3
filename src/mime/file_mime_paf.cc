//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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

// file_mime_paf.cc author Hui Cao <huica@cisco.com>
// 9.25.2012 - Initial Source Code. Hui Cao

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mime_paf.h"

#include <cctype>

#include "main/snort_module.h"
#include "trace/trace_api.h"

using namespace snort;

static const char* boundary_str = "boundary=";

static inline bool handle_quoted(MimeDataPafInfo* data_info, uint8_t val)
{
    if (val == '"')
    {
        /* Trim trailing spaces before closing quote */
        while (data_info->boundary_len > 0 and
            isspace(data_info->boundary[data_info->boundary_len - 1]))
            data_info->boundary_len--;

        /* Closing quote - finalize boundary */
        data_info->boundary[data_info->boundary_len] = '\0';
        return true;
    }

    /* Inside quotes - add everything including spaces
    until boundary limit is reached + reserve space for 0-terminator */
    if (data_info->boundary_len < (int)sizeof(data_info->boundary) - 1)
    {
        data_info->boundary[data_info->boundary_len++] = val;
    }
    else
    {
        /* Trim trailing spaces */
        while (data_info->boundary_len > 0 and
            isspace(data_info->boundary[data_info->boundary_len - 1]))
            data_info->boundary_len--;

        /* Reached MAX allowed boundary len */
        data_info->boundary[data_info->boundary_len] = '\0';
        return true;
    }

    return false;
}

/* Save the boundary string into paf state */
static inline bool store_boundary(MimeDataPafInfo* data_info, uint8_t val)
{
    if (!data_info->boundary_search)
    {
        if ((val == '.') or isspace(val))
            data_info->boundary_search = boundary_str;
        return false;
    }

    if (*(data_info->boundary_search) == '=')
    {
        /* Skip spaces for the end of boundary */
        if (val == '=')
            data_info->boundary_search++;
        else if (!isspace(val))
            data_info->boundary_search = nullptr;
    }
    else if (*(data_info->boundary_search) == '\0')
    {
        /* Handle opening quote - first character after '=' */
        if (!data_info->boundary_len and !data_info->boundary_quoted and val == '"')
        {
            data_info->boundary_quoted = true;
            return false;  /* Skip the quote itself */
        }

        if (data_info->boundary_quoted)
        {
            return handle_quoted(data_info, val);
        }

        /* Unquoted mode - check terminators */
        if ((val == ';') or isspace(val))
        {
            if (!data_info->boundary_len)
                return false;
            else
            {
                /* Found boundary string */
                data_info->boundary[data_info->boundary_len] = '\0';
                return true;
            }
        }
        /* Need to subtract the size allocated for 0-terminator */
        if (data_info->boundary_len < (int)sizeof(data_info->boundary) - 1)
        {
            data_info->boundary[data_info->boundary_len++] = val;
        }
        else
        {
            /* Reached MAX allowed boundary len */
            assert(data_info->boundary_len == sizeof(data_info->boundary) - 1);
            data_info->boundary[sizeof(data_info->boundary) - 1] = '\0';

            return true;
        }
    }
    else if ((val == *(data_info->boundary_search))
        or (val == *(data_info->boundary_search) - 'a' + 'A'))
    {
        data_info->boundary_search++;
    }
    else
    {
        if ((val == '.') or isspace(val))
            data_info->boundary_search = boundary_str;
        else
            data_info->boundary_search = nullptr;
    }

    return false;
}

/* check the boundary string in the mail body*/
static inline bool check_boundary(MimeDataPafInfo* data_info, uint8_t data)
{
    const auto prev_state = data_info->boundary_state;

    /* Search for boundary signature "{CRLF}--"*/
    switch (data_info->boundary_state)
    {
    case MIME_PAF_BOUNDARY_UNKNOWN:
        if (data == '\r')
            data_info->boundary_state = MIME_PAF_BOUNDARY_CR;
        else if (data == '\n')
            data_info->boundary_state = MIME_PAF_BOUNDARY_LF;
        else if (data == '-' && data_info->data_state == MIME_PAF_FOUND_FIRST_BOUNDARY_STATE)
            data_info->boundary_state = MIME_PAF_BOUNDARY_HYPEN_FIRST;
        else
            return false;
        break;

    case MIME_PAF_BOUNDARY_CR:
        if (data == '\n')
            data_info->boundary_state = MIME_PAF_BOUNDARY_LF;
        else if (data == '\r')
            data_info->boundary_state = MIME_PAF_BOUNDARY_CR;
        else
            data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
        break;

    case MIME_PAF_BOUNDARY_LF:
        if (data == '-')
            data_info->boundary_state = MIME_PAF_BOUNDARY_HYPEN_FIRST;
        else if (data == '\r')
            data_info->boundary_state = MIME_PAF_BOUNDARY_CR;
        else if (data == '\n')
            data_info->boundary_state = MIME_PAF_BOUNDARY_LF;
        else
            data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
        break;

    case MIME_PAF_BOUNDARY_HYPEN_FIRST:
        if (data == '-')
        {
            data_info->boundary_state = MIME_PAF_BOUNDARY_HYPEN_SECOND;
            data_info->boundary_search = data_info->boundary;
        }
        else if (data == '\r')
            data_info->boundary_state = MIME_PAF_BOUNDARY_CR;
        else if (data == '\n')
            data_info->boundary_state = MIME_PAF_BOUNDARY_LF;
        else
            data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
        break;

    case MIME_PAF_BOUNDARY_HYPEN_SECOND:
        /* Compare with boundary string stored */
        if (*(data_info->boundary_search) == '\0')
        {
            if (data == '\n')
            {
                /*reset boundary search etc.*/
                data_info->boundary_search_len += 1;
                data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
                return true;
            }
            else if (data != '\r' && data != '-' && data != ' ' && data != '\t')
                data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
        }
        else if (*(data_info->boundary_search) == data)
            data_info->boundary_search++;
        else if (data == '\r')
            data_info->boundary_state = MIME_PAF_BOUNDARY_CR;
        else if (data == '\n')
            data_info->boundary_state = MIME_PAF_BOUNDARY_LF;
        else
            data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
        break;
    }

    if (MIME_PAF_BOUNDARY_UNKNOWN == data_info->boundary_state)
        data_info->boundary_search_len = 0;
    else if (prev_state >= data_info->boundary_state && prev_state != MIME_PAF_BOUNDARY_HYPEN_SECOND)
        data_info->boundary_search_len = 1;
    else
        data_info->boundary_search_len += 1;

    return false;
}

namespace snort
{
void reset_mime_paf_state(MimeDataPafInfo* data_info)
{
    data_info->boundary_search = nullptr;
    data_info->boundary_search_len = 0;
    data_info->boundary_len = 0;
    data_info->boundary[0] = '\0';
    data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
    data_info->data_state = MIME_PAF_FINDING_BOUNDARY_STATE;
    data_info->boundary_quoted = false;
}

/*  Process data boundary and flush each file based on boundary*/
bool process_mime_paf_data(MimeDataPafInfo* data_info, uint8_t data)
{
    switch (data_info->data_state)
    {
    case MIME_PAF_FINDING_BOUNDARY_STATE:
        if (store_boundary(data_info, data))
        {
            debug_logf(snort_trace, TRACE_MIME, nullptr, "MIME boundary found: %s\n", data_info->boundary);

            data_info->data_state = MIME_PAF_FOUND_FIRST_BOUNDARY_STATE;
        }
        break;

    case MIME_PAF_FOUND_FIRST_BOUNDARY_STATE:
    case MIME_PAF_FOUND_BOUNDARY_STATE:
        if (check_boundary(data_info,  data))
        {
            data_info->data_state = MIME_PAF_FOUND_BOUNDARY_STATE;
            return true;
        }
        break;

    default:
        break;
    }

    return false;
}

bool check_data_end(void* data_end_state, uint8_t val)
{
    DataEndState state =  *((DataEndState*)data_end_state);

    switch (state)
    {
    case PAF_DATA_END_UNKNOWN:
        if (val == '\n')
        {
            state = PAF_DATA_END_FIRST_LF;
        }
        break;

    case PAF_DATA_END_FIRST_LF:
        if (val == '.')
        {
            state = PAF_DATA_END_DOT;
        }
        else if ((val != '\r') && (val != '\n'))
        {
            state = PAF_DATA_END_UNKNOWN;
        }
        break;
    case PAF_DATA_END_DOT:
        if (val == '\n')
        {
            *((DataEndState*)data_end_state) = PAF_DATA_END_UNKNOWN;
            return true;
        }
        else if (val != '\r')
        {
            state = PAF_DATA_END_UNKNOWN;
        }
        break;

    default:
        state = PAF_DATA_END_UNKNOWN;
        break;
    }

    *((DataEndState*)data_end_state) = state;
    return false;
}
} // namespace snort

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

#include <cstring>

using namespace snort;

static void process_boundary_value(MimeDataPafInfo* info, const char* boundary_part)
{
    info->boundary_search = boundary_str;

    while (*boundary_part and !store_boundary(info, *boundary_part++))
    { }
}

TEST_CASE("MIME boundary parsing", "[mime]")
{
    MimeDataPafInfo info;

    SECTION("quoted boundary with spaces")
    {
        // Spaces are accepted in quoted-string boundaries
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary= \"boundary 123 foobar\"");

        CHECK(strcmp(info.boundary, "boundary 123 foobar") == 0);
        CHECK(info.boundary_len == 19);
    }

    SECTION("unquoted boundary with spaces")
    {
        // Unquoted boundary must be a valid "token" (per RFC 2045),
        // and therefore stops at the first character not allowed in a token.
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary=boundary 123  foobar");

        CHECK(strcmp(info.boundary, "boundary") == 0);
        CHECK(info.boundary_len == 8);
    }

    SECTION("quoted boundary with trailing spaces inside")
    {
        // RFC 2046: spaces at the end of the boundary is forbidden
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary=\"foobar  \"");

        CHECK(strcmp(info.boundary, "foobar") == 0);
        CHECK(info.boundary_len == 6);
    }

    SECTION("quoted boundary with leading spaces")
    {
        // Leading spaces in quoted-string are not strictly forbidden by standard
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary=\"  foobar\"");

        CHECK(strcmp(info.boundary, "  foobar") == 0);
        CHECK(info.boundary_len == 8);
    }

    SECTION("unquoted boundary with trailing spaces")
    {
        // RFC 2046: spaces at the end of the boundary is forbidden
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary=foobar  ;");

        CHECK(strcmp(info.boundary, "foobar") == 0);
        CHECK(info.boundary_len == 6);
    }

    SECTION("unquoted boundary with leading spaces")
    {
        // Token(unquoted boundary) cannot start with spaces, they will be skipped
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary=  foobar");

        CHECK(strcmp(info.boundary, "foobar") == 0);
        CHECK(info.boundary_len == 6);
    }

    SECTION("simple quoted boundary with spaces after boundary keyword")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary  =\"foobar\"");

        CHECK(strcmp(info.boundary, "foobar") == 0);
        CHECK(info.boundary_len == 6);
    }

    SECTION("simple unquoted boundary with spaces after boundary keyword")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary  =foobar");

        CHECK(strcmp(info.boundary, "foobar") == 0);
        CHECK(info.boundary_len == 6);
    }

    SECTION("boundary with special chars")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary=\"-=_boundary_+=\"");

        CHECK(strcmp(info.boundary, "-=_boundary_+=") == 0);
        CHECK(info.boundary_len == 14);
    }

    SECTION("case insensitive boundary keyword")
    {
        // The keyword "boundary" should be case-insensitive
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "BOUNDARY=foobar");

        CHECK(strcmp(info.boundary, "foobar") == 0);
        CHECK(info.boundary_len == 6);
    }

    SECTION("empty quoted boundary")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary=\"\"");

        CHECK(info.boundary_len == 0);
    }

    SECTION("quoted spaces boundary")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary=\"     \"");

        CHECK(info.boundary_len == 0);
    }

    SECTION("boundary with equals sign")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary=\"boundary=foobar\"");

        CHECK(strcmp(info.boundary, "boundary=foobar") == 0);
        CHECK(info.boundary_len == 15);
    }

    SECTION("boundary without =")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary\"--foobar\"");

        CHECK(strcmp(info.boundary, "") == 0);
        CHECK(info.boundary_len == 0);
    }

    SECTION("another option after boundary ")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "Content-Type: multipart/form-data; boundary=foobar charset=utf-8");

        CHECK(strcmp(info.boundary, "foobar") == 0);
        CHECK(info.boundary_len == 6);
    }

    SECTION("quoted boundary with semicolon after closing quote")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary= \"foobar 123\";");

        CHECK(strcmp(info.boundary, "foobar 123") == 0);
        CHECK(info.boundary_len == 10);
    }

    SECTION("show case - quoted boundary without closing quote and semicolon")
    {
        // In quoted mode, semicolon is part of the boundary value
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary= \"foobar 123; charset=utf-8");

        CHECK(strcmp(info.boundary, "foobar 123; charset=utf-8") == 0);
        CHECK(info.boundary_len == 25);
    }

    SECTION("unquoted boundary with quote at the end")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        process_boundary_value(&info, "boundary= foobar 123\"");

        CHECK(strcmp(info.boundary, "foobar") == 0);
        CHECK(info.boundary_len == 6);
    }

    SECTION("quoted boundary overflow - exceeds MAX_MIME_BOUNDARY_LEN")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        // 75 chars boundary - should trigger overflow protection
        process_boundary_value(&info, "boundary=\"123456789012345678901234567890123456789012345678901234567890123456789_EXTRA\"");

        CHECK(info.boundary_len == MAX_MIME_BOUNDARY_LEN);
        CHECK(strcmp(info.boundary, "123456789012345678901234567890123456789012345678901234567890123456789_") == 0);
        CHECK(info.boundary[MAX_MIME_BOUNDARY_LEN] == '\0');

        reset_mime_paf_state(&info);
        process_boundary_value(&info, "boundary=\"     123456789012345678901234567890123456789012345678901234567890123456789_\"");
        CHECK(strcmp(info.boundary, "     12345678901234567890123456789012345678901234567890123456789012345") == 0);
        CHECK(info.boundary[info.boundary_len] == '\0');

        reset_mime_paf_state(&info);
        process_boundary_value(&info, "boundary=\"123456789012345678901234567890123456789012345678901234567890123456789_     \"");
        CHECK(strcmp(info.boundary, "123456789012345678901234567890123456789012345678901234567890123456789_") == 0);
        CHECK(info.boundary[info.boundary_len] == '\0');

        reset_mime_paf_state(&info);
        process_boundary_value(&info, "boundary=\"     123456789012345678901234567890123456789012345678901234567890123456789_     \"");
        CHECK(strcmp(info.boundary, "     12345678901234567890123456789012345678901234567890123456789012345") == 0);
        CHECK(info.boundary[info.boundary_len] == '\0');

        reset_mime_paf_state(&info);
        process_boundary_value(&info, "boundary=\"12345678901234567890123456789012345678901234567890123456789                \"");
        CHECK(strcmp(info.boundary, "12345678901234567890123456789012345678901234567890123456789") == 0);
        CHECK(info.boundary[info.boundary_len] == '\0');
    }

    SECTION("unquoted boundary overflow - exceeds MAX_MIME_BOUNDARY_LEN")
    {
        memset(&info, 0, sizeof(info));
        reset_mime_paf_state(&info);

        // 75 chars boundary - should trigger overflow protection
        process_boundary_value(&info, "boundary=123456789012345678901234567890123456789012345678901234567890123456789_EXTRA");

        CHECK(info.boundary_len == MAX_MIME_BOUNDARY_LEN);
        CHECK(strcmp(info.boundary, "123456789012345678901234567890123456789012345678901234567890123456789_") == 0);
        CHECK(info.boundary[MAX_MIME_BOUNDARY_LEN] == '\0');

        reset_mime_paf_state(&info);
        process_boundary_value(&info, "boundary=     123456789012345678901234567890123456789012345678901234567890123456789_");
        CHECK(strcmp(info.boundary, "123456789012345678901234567890123456789012345678901234567890123456789_") == 0);
        CHECK(info.boundary[info.boundary_len] == '\0');

        reset_mime_paf_state(&info);
        process_boundary_value(&info, "boundary=123456789012345678901234567890123456789012345678901234567890123456789_     ");
        CHECK(strcmp(info.boundary, "123456789012345678901234567890123456789012345678901234567890123456789_") == 0);
        CHECK(info.boundary[info.boundary_len] == '\0');

        reset_mime_paf_state(&info);
        process_boundary_value(&info, "boundary=     123456789012345678901234567890123456789012345678901234567890123456789_     ");
        CHECK(strcmp(info.boundary, "123456789012345678901234567890123456789012345678901234567890123456789_") == 0);
        CHECK(info.boundary[info.boundary_len] == '\0');

        reset_mime_paf_state(&info);
        process_boundary_value(&info, "boundary=12345678901234567890123456789012345678901234567890123456789                ");
        CHECK(strcmp(info.boundary, "12345678901234567890123456789012345678901234567890123456789") == 0);
        CHECK(info.boundary[info.boundary_len] == '\0');
    }
}

#endif
