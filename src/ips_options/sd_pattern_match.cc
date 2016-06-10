//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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

// sd_pattern_match.cc author Ryan Jordan

#include "sd_pattern_match.h"
#include "sd_credit_card.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "log/messages.h"
#include "utils/util.h"

SdOptionData::SdOptionData(std::string pattern_, bool obfuscate_)
{
    if (pattern_ == "credit_card")
    {
        pattern_ = SD_CREDIT_PATTERN_ALL;
        validate = SdLuhnAlgorithm;
        obfuscate_pii = obfuscate_;
    }

    else if (pattern_ == "us_social")
    {
        pattern_ = SD_SOCIAL_PATTERN;
        obfuscate_pii = obfuscate_;
    }

    else if (pattern_ == "us_social_nodashes")
    {
        pattern_ = SD_SOCIAL_NODASHES_PATTERN;
        obfuscate_pii = obfuscate_;
    }

    pattern = snort_strdup(pattern_.c_str());
    ExpandBrackets();
}

void SdOptionData::ExpandBrackets()
{
    char* bracket_index, * new_pii, * endptr, * pii_position;
    unsigned long int new_pii_size, repetitions, total_reps = 0;
    unsigned int num_brackets = 0;

    if ( !pattern )
        return;

    bracket_index = strchr(pattern, '{');

    if ( bracket_index == pattern )
        ParseError("sd_pattern \"%s\" starts with curly brackets which have nothing to modify.", pattern);

    while ( bracket_index )
    {
        if ( (bracket_index > pattern) && (*(bracket_index-1) == '\\') )
        {
            // Ignore escaped brackets
            bracket_index = strchr(bracket_index+1, '{');
            continue;
        }

        // Check for the case of one bracket set modifying another, i.e. "{3}{4}"
        // Note: "\}{4}" is OK
        if ( (bracket_index > pattern + 1) && (*(bracket_index - 1) == '}') && (*(bracket_index - 2) != '\\') )
            ParseError("sd_pattern \"%s\" contains curly brackets which have nothing to modify.", pattern);

        repetitions = strtoul(bracket_index+1, &endptr, 10);

        if ( *endptr != '}' && *endptr != '\0' )
            ParseError("sd_pattern \"%s\" contains curly brackets with non-digits inside.", pattern);

        else if (*endptr == '\0')
            ParseError("sd_pattern \"%s\" contains an unterminated curly bracket.", pattern);

        if ( (bracket_index > pattern+1) && (*(bracket_index-2) == '\\') )
            total_reps += (repetitions * 2);
        else
            total_reps += repetitions;

        num_brackets++;

        bracket_index = strchr(bracket_index+1, '{');
    }

    if ( num_brackets == 0 )
        return;

    new_pii_size = (strlen(pattern) + total_reps - 2 * num_brackets + 1);
    new_pii = (char*)snort_calloc(new_pii_size, sizeof(*new_pii));

    pii_position = pattern;

    while (*pii_position != '\0')
    {
        char repeated_section[3] = {'\0'};
        unsigned long int i, reps = 1;

        repeated_section[0] = pii_position[0];
        pii_position++;

        if ( repeated_section[0] == '\\'
          && pii_position[0] != '\0' )
        {
            repeated_section[1] = pii_position[0];
            pii_position++;
        }

        if ( pii_position[0] == '{' )
        {
            reps = strtoul(pii_position+1, &endptr, 10);
            pii_position = endptr+1;
        }

        for (i = 0; i < reps; i++)
            strncat(new_pii, repeated_section, 2);
    }

    snort_free(pattern);
    pattern = new_pii;
}

bool SdOptionData::match(const uint8_t * const buf, uint16_t * const buf_index, uint16_t buflen)
{
    uint16_t pattern_index = 0;
    bool node_match = true;

    while ( *buf_index < buflen && pattern[pattern_index] != '\0' && node_match )
    {
        char const * const pc = &pattern[pattern_index];

        if ( pc[0] == '\\' && pc[1] != '\0' )
        {
match__rescan:
            pattern_index++;
            switch ( pattern[pattern_index] )
            {
                // Escaped special character
                case '\\':
                case '{':
                case '}':
                case '?':
                    node_match = (buf[*buf_index] == pattern[pattern_index]);
                    break;

                // \d : match digit
                case 'd':
                    node_match = isdigit((int)buf[*buf_index]);
                    break;

                // \D : match non-digit
                case 'D':
                    node_match = !isdigit((int)buf[*buf_index]);
                    break;

                // \w : match alphanumeric
                case 'w':
                    node_match = isalnum((int)buf[*buf_index]);
                    break;

                // \W : match non-alphanumeric */
                case 'W':
                    node_match = !isalnum((int)buf[*buf_index]);
                    break;

                // \l : match a letter
                case 'l':
                    node_match = isalpha((int)buf[*buf_index]);
                    break;

                // \L : match a non-letter
                case 'L':
                    node_match = !isalpha((int)buf[*buf_index]);
                    break;

                // \b : match a numeric boundary
                case 'b':
                    node_match = !isdigit((int)buf[*buf_index]);
                    if ( !node_match && *buf_index == 0
                      && pattern[pattern_index+1] != '\0'
                      && pattern[pattern_index+2] != '\0' )
                    {
                        pattern_index++;
                        goto match__rescan;
                    }
            }
        }
        else
        {
            // Normal byte match
            node_match = (buf[*buf_index] == pattern[pattern_index]);
        }

        // Handle optional characters
        if (pattern[pattern_index + 1] == '?')
        {
            pattern_index += 2;
            if (node_match)
                (*buf_index)++;
            else
                node_match = true;
        }
        else
        {
            (*buf_index)++;
            pattern_index++;
        }
    }

    if ( !node_match )
        return false;

    if( *buf_index == buflen )
    {
        char const * const pc = &pattern[pattern_index];

        // '\b' can match EOM
        if ( !(pc[0] == '\\' && pc[1] == 'b') )
        {
            if( (pc[0] == '\0') )
                return true;

            else
                return false;
        }
    }

    if ( validate && validate(buf, *buf_index) != 1 )
        return false;

    // Success!
    return true;
}

