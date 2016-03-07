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

int AddPiiPiece(SdTreeNode *node, char *new_pattern, SdOptionData *data);
SdTreeNode* AddChild(SdTreeNode *node, SdOptionData *data, char *pattern);


SdOptionData::SdOptionData(std::string pattern, uint8_t threshold)
{
    validate_func = nullptr;
    match_success = 0;

    if (pattern == "credit_card")
    {
        pattern = SD_CREDIT_PATTERN_ALL;
        validate_func = SdLuhnAlgorithm;
    }
    else if (pattern == "us_social")
        pattern = SD_SOCIAL_PATTERN;
    else if (pattern == "us_social_nodashes")
        pattern = SD_SOCIAL_NODASHES_PATTERN;

    pii = strdup(pattern.c_str());
    if (!pii)
        FatalError("Failed to copy sd_pattern");

    count = threshold;
}

SdContext::SdContext(SdOptionData *sd_data)
{
    head_node = (SdTreeNode*)calloc(1, sizeof(*head_node));
    if (!head_node)
        FatalError("Failed to allocate SdContext node\n");

    sd_data->counter_index = num_patterns++;
    AddPii(head_node, sd_data);
}

// Main pattern-adding function.
// Arguments:
//  head => pointer to top node in PII tree
//  data => pointer to SdOptionData struct w/ new pattern
// Return values:
//  -1: error
//   1: pattern added successfully
//
static int AddPiiPattern(SdTreeNode *head, SdOptionData *data)
{
    AddChild(head, data, data->pii);
    return 1;
}

// Check that the brackets in a pattern match up, and only contain numbers.
//
// Arguments:
//   pii - string containing pattern.
//
// Returns: void function. Raises fatal error if there's a problem.
//
static void ExpandBrackets(char **pii)
{
    char *bracket_index, *new_pii, *endptr, *pii_position;
    unsigned long int new_pii_size, repetitions, total_reps = 0;
    unsigned int num_brackets = 0;

    if (pii == NULL || *pii == NULL)
        return;

    // Locate first '{'
    bracket_index = strchr(*pii, '{');

    // Brackets at the beginning have nothing to modify.
    if (bracket_index == *pii)
    {
        ParseError("sd_pattern \"%s\" starts with curly brackets which have nothing to modify.\n", *pii);
    }

    // Check for various error cases. Total up the # of bytes needed in new pattern
    while (bracket_index)
    {
        // Ignore escaped brackets 
        if ((bracket_index > *pii) && (*(bracket_index-1) == '\\'))
        {
            bracket_index = strchr(bracket_index+1, '{');
            continue;
        }

        // Check for the case of one bracket set modifying another, i.e. "{3}{4}"
        // Note: "\}{4}" is OK
        if ((bracket_index > (*pii)+1) &&
            (*(bracket_index-1) == '}') &&
            (*(bracket_index-2) != '\\') )
        {
            ParseError("sd_pattern \"%s\" contains curly brackets which have nothing to modify.\n", *pii);
        }

        // Get the number from inside the brackets
        repetitions = strtoul(bracket_index+1, &endptr, 10);
        if (*endptr != '}' && *endptr != '\0')
        {
            ParseError("sd_pattern \"%s\" contains curly brackets with non-digits inside.\n", *pii);
        }
        else if (*endptr == '\0')
        {
            ParseError("sd_pattern \"%s\" contains an unterminated curly bracket.\n", *pii);
        }

        // The brackets look OK. Increase the rep count.
        if ((bracket_index > (*pii)+1) && (*(bracket_index-2) == '\\'))
            total_reps += (repetitions * 2);
        else
            total_reps += repetitions;

        num_brackets++;

        // Next bracket
        bracket_index = strchr(bracket_index+1, '{');
    }

    // By this point, the brackets all match up.
    if (num_brackets == 0)
        return;

    // Allocate the new pii string.
    new_pii_size = (strlen(*pii) + total_reps - 2*num_brackets + 1);
    new_pii = (char*)calloc(new_pii_size, sizeof(char));
    if (new_pii == NULL)
    {
        FatalError("Failed to allocate memory for sd_pattern rule option\n");
    }

    // Copy the PII string, expanding repeated sections.
    pii_position = *pii;
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

        // Channeling "Shlemiel the Painter" here.
        for (i = 0; i < reps; i++)
        {
            strncat(new_pii, repeated_section, 2);
        }
    }

    // Switch out the pii strings.
    free(*pii);
    *pii = new_pii;
}

// Perform any modifications needed to a pattern string, then add it to the
// tree.
int AddPii(SdTreeNode *head, SdOptionData *data)
{
    ExpandBrackets(&(data->pii));

    return AddPiiPattern(head, data);
}

// Create a new tree node, and add it as a child to the current node.
SdTreeNode * AddChild(SdTreeNode *node, SdOptionData *data, char *pattern)
{
    SdTreeNode * new_node = NULL;

    // Take care not to step on the other children
    node->children = (SdTreeNode**)calloc(1,sizeof(SdTreeNode*));
    if (node->children == NULL)
    {
        FatalError("Could not allocate node children\n");
    }

    node->children[0] = (SdTreeNode*)calloc(1,sizeof(SdTreeNode));
    if (node->children[0] == NULL)
    {
        FatalError("Could not allocate node children[0]\n");
    }

    node->num_children = 1;
    new_node = node->children[0];

    new_node->pattern = strdup(pattern);
    if (new_node->pattern == NULL)
    {
        FatalError("Could not allocate node pattern\n");
    }

    new_node->num_option_data = 1;
    new_node->option_data_list = (SdOptionData**)calloc(1, sizeof(SdOptionData*));
    if (new_node->option_data_list == NULL)
    {
        FatalError("Could not allocate node list\n");
    }

    new_node->option_data_list[0] = data;

    return new_node;
}

// Frees an entire PII tree.
int FreePiiTree(SdTreeNode *node)
{
    uint16_t i;

    for (i = 0; i < node->num_children; i++)
    {
        FreePiiTree(node->children[i]);
    }

    free(node->pattern);
    free(node->children);

    for (i = 0; i < node->num_option_data; i++)
        delete node->option_data_list[i];

    free(node->option_data_list);
    free(node);

    return 0;
}

// Returns an SdTreeNode that matches the pattern
SdTreeNode * FindPiiRecursively(SdTreeNode *node, const uint8_t *buf, uint16_t *buf_index,
        uint16_t buflen, uint16_t *partial_index, SdTreeNode **partial_node)
{
    uint16_t old_buf_index;
    uint16_t pattern_index = *partial_index;
    int node_match = 1;

    *partial_index = 0;
    *partial_node = NULL;

    old_buf_index = *buf_index;

    // NOTE: node->pattern is a NULL-terminated string, but buf is network data
    //       and may legitimately contain NULL bytes.
    while (*buf_index < buflen &&
           *(node->pattern + pattern_index) != '\0' &&
           node_match )
    {
        // Match a byte at a time.
        if ( *(node->pattern + pattern_index) == '\\' &&
             *(node->pattern + pattern_index + 1) != '\0' )
        {
            // Escape sequence found
            pattern_index++;
            switch ( *(node->pattern + pattern_index) )
            {
                // Escaped special character
                case '\\':
                case '{':
                case '}':
                case '?':
                    node_match = (*(buf + *buf_index) == *(node->pattern + pattern_index));
                    break;

                // \d : match digit
                case 'd':
                    node_match = isdigit( (int)(*(buf + *buf_index)) );
                    break;
                // \D : match non-digit
                case 'D':
                    node_match = !isdigit( (int)(*(buf + *buf_index)) );
                    break;

                // \w : match alphanumeric
                case 'w':
                    node_match = isalnum( (int)(*(buf + *buf_index)) );
                    break;
                // \W : match non-alphanumeric */
                case 'W':
                    node_match = !isalnum( (int)(*(buf + *buf_index)) );
                    break;

                // \l : match a letter
                case 'l':
                    node_match = isalpha( (int)(*(buf + *buf_index)) );
                    break;
                // \L : match a non-letter
                case 'L':
                    node_match = !isalpha( (int)(*(buf + *buf_index)) );
                    break;
            }
        }
        else
        {
            // Normal byte
            node_match = (*(buf + *buf_index) == *(node->pattern + pattern_index));
        }

        // Handle optional characters
        if (*(node->pattern + pattern_index + 1) == '?')
        {
            // Advance past the '?' in the pattern string.
            // Only advance in the buffer if we matched the optional char.
            pattern_index += 2;
            if (node_match)
                (*buf_index)++;
            else
                node_match = 1;
        }
        else
        {
            // Advance to next byte
            (*buf_index)++;
            pattern_index++;
        }
    }

    if (node_match)
    {
        uint16_t j;
        bool node_contains_matches = false;
        SdTreeNode *matched_node = NULL;

        if(*buf_index == buflen)
        {
            if( (*(node->pattern + pattern_index) != '\0')
              || ((strlen(node->pattern) == pattern_index) && node->num_children))
            {
                *partial_index = pattern_index;
                *partial_node = node;
                return NULL;
            }
        }

        if ( matched_node || *partial_index )
            return matched_node;

        // An SdTreeNode holds multiple SdOptionData. It's possible to get
        // some with validation funs and some without. Evaluate them independently.
        for (j = 0; j < node->num_option_data; j++)
        {
            SdOptionData *option_data = node->option_data_list[j];

            // Run eval func, return NULL if it exists but fails
            if ( option_data->validate_func
              && option_data->validate_func(buf, *buf_index) != 1 )
            {
                *buf_index = old_buf_index;
                option_data->match_success = 0;
            }
            else
            {
                // No eval func necessary, or an eval func existed and returned 1
                option_data->match_success = 1;
                node_contains_matches = true;
            }
        }

        if (node_contains_matches)
            return node;
    }

    // No match here.
    *buf_index = old_buf_index;
    return NULL;
}

SdTreeNode * FindPii(const SdTreeNode *head, 
        const uint8_t *buf, uint16_t *buf_index, uint16_t buflen,
        SdSessionData *session)
{
    uint16_t i;
    uint16_t *partial_index = &(session->part_match_index);
    SdTreeNode **partial_node = &(session->part_match_node);
    *partial_index = 0;

    for (i = 0; i < head->num_children; i++)
    {
        SdTreeNode * matched_node = FindPiiRecursively(head->children[i], 
                buf, buf_index, buflen, partial_index, partial_node);
        
        if (matched_node || *partial_index)
            return matched_node;
    }

    return NULL;
}

