//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// service_mdns.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_mdns.h"

#include "app_info_table.h"
#include "appid_module.h"
#include "protocols/packet.h"
#include "search_engines/search_tool.h"

using namespace snort;

#define MDNS_PORT   5353
#define PATTERN_REFERENCE_PTR   3
#define PATTERN_STR_LOCAL_1           "\005local"
#define PATTERN_STR_LOCAL_2           "\005LOCAL"
#define PATTERN_STR_ARPA_1           "\004arpa"
#define PATTERN_STR_ARPA_2           "\004ARPA"
#define PATTERN_USERNAME_1           '@'
#define MDNS_PATTERN1 "\x00\x00\x84\x00\x00\x00"
#define MDNS_PATTERN2 "\x00\x00\x08\x00\x00\x00"
#define MDNS_PATTERN3 "\x00\x00\x04\x00\x00\x00"
#define MDNS_PATTERN4 "\x00\x00\x00\x00"
#define SRV_RECORD "\x00\x21"
#define SRV_RECORD_OFFSET  6
#define LENGTH_OFFSET 8
#define NEXT_MESSAGE_OFFSET 10
#define QUERY_OFFSET 4
#define ANSWER_OFFSET 6
#define RECORD_OFFSET 12
#define SHIFT_BITS 8
#define SHIFT_BITS_REFERENCE_PTR  6
#define REFERENCE_PTR_LENGTH  2
#define MAX_LENGTH_SERVICE_NAME 256

enum MDNSState
{
    MDNS_STATE_CONNECTION,
    MDNS_STATE_CONNECTION_ERROR
};

struct ServiceMDNSData
{
    MDNSState state;
};

struct MdnsPattern
{
    const uint8_t* pattern;
    unsigned length;
};

struct MatchedPatterns
{
    MdnsPattern* mpattern;
    int match_start_pos;
    MatchedPatterns* next;
};

static THREAD_LOCAL MatchedPatterns* patternList;
static THREAD_LOCAL MatchedPatterns* patternFreeList;

static MdnsPattern patterns[] =
{
    { (const uint8_t*)PATTERN_STR_LOCAL_1, sizeof(PATTERN_STR_LOCAL_1) - 1 },
    { (const uint8_t*)PATTERN_STR_LOCAL_2, sizeof(PATTERN_STR_LOCAL_2) - 1 },
    { (const uint8_t*)PATTERN_STR_ARPA_1, sizeof(PATTERN_STR_ARPA_1) - 1 },
    { (const uint8_t*)PATTERN_STR_ARPA_2, sizeof(PATTERN_STR_ARPA_2) - 1 },
};

MdnsServiceDetector::MdnsServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "MDNS";
    proto = IpProtocol::UDP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_MDNS, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { 5353, IpProtocol::UDP, false },
    };

    matcher = new snort::SearchTool("ac_full", true);
    for (unsigned i = 0; i < sizeof(patterns) / sizeof(*patterns); i++)
        matcher->add((const char*)patterns[i].pattern, patterns[i].length, &patterns[i]);
    matcher->prep();

    handler->register_detector(name, this, proto);
}

MdnsServiceDetector::~MdnsServiceDetector()
{
    destory_matcher();
}

void MdnsServiceDetector::release_thread_resources()
{   
    MatchedPatterns* node;

    destroy_match_list();

    while ((node = patternFreeList))
    {
        patternFreeList = node->next;
        snort_free(node);
    }
}

int MdnsServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    int ret_val;

    ServiceMDNSData* fd = (ServiceMDNSData*)data_get(args.asd);
    if (!fd)
    {
        fd = (ServiceMDNSData*)snort_calloc(sizeof(ServiceMDNSData));
        data_add(args.asd, fd, &snort_free);
        fd->state = MDNS_STATE_CONNECTION;
    }

    if (args.pkt->ptrs.dp == MDNS_PORT || args.pkt->ptrs.sp == MDNS_PORT )
    {
        ret_val = validate_reply(args.data, args.size);
        if (ret_val == 1)
        {
            if (args.config->mod_config->mdns_user_reporting)
            {
                analyze_user(args.asd, args.pkt, args.size);
                destroy_match_list();
                goto success;
            }
            goto success;
        }
        else
            goto fail;
    }
    else
        goto fail;

success:
    return add_service(args.asd, args.pkt, args.dir, APP_ID_MDNS);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

int MdnsServiceDetector::validate_reply(const uint8_t* data, uint16_t size)
{
    int ret_val;

    /* Check for the pattern match*/
    if (size >= 6 && memcmp(data, MDNS_PATTERN1, sizeof(MDNS_PATTERN1)-1) == 0)
        ret_val = 1;
    else if (size >= 6 && memcmp(data, MDNS_PATTERN2,  sizeof(MDNS_PATTERN2)-1) == 0)
        ret_val = 1;
    else if (size >= 6 && memcmp(data,MDNS_PATTERN3, sizeof(MDNS_PATTERN3)-1) == 0)
        ret_val = 1;
    else if (size >= 4 && memcmp(data,MDNS_PATTERN4, sizeof(MDNS_PATTERN4)-1) == 0)
        ret_val = 1;
    else
        ret_val = 0;

    return ret_val;
}

/* Input to this function is start_ptr and data_size.
   Output is resp_endptr, start_index and user_name_len
   Returns 0 or 1 for successful/unsuccessful hit for pattern '@'
   Returns -1 for invalid address pointer or past the data_size */
int MdnsServiceDetector::reference_pointer(const char* start_ptr, const char** resp_endptr,
    int* start_index,
    uint16_t data_size, uint8_t* user_name_len, unsigned size)
{
    int index = 0;
    int pattern_length = 0;

    while (index< data_size &&  (start_ptr[index] == ' ' ))
        index++;

    if (index >= data_size)
        return -1;
    *start_index = index;

    const char* temp_start_ptr;
    temp_start_ptr  = start_ptr+index;

    // FIXIT-M - This code needs review to ensure it works correctly with the new semantics of the
    //           index returned by the SearchTool find_all pattern matching function
    scan_matched_patterns(start_ptr, size - data_size + index, resp_endptr, &pattern_length);
    /* Contains reference pointer */
    while ((index < data_size) && !(*resp_endptr) && ((uint8_t )temp_start_ptr[index]  >>
        SHIFT_BITS_REFERENCE_PTR  != PATTERN_REFERENCE_PTR))
    {
        if (temp_start_ptr[index] == PATTERN_USERNAME_1)
        {
            *user_name_len = index - *start_index;
            index++;
            break;
        }
        index++;
        scan_matched_patterns(start_ptr, size - data_size + index, resp_endptr, &pattern_length);
    }
    if (index >= data_size)
        *user_name_len = 0;
    else if ((uint8_t )temp_start_ptr[index]  >> SHIFT_BITS_REFERENCE_PTR == PATTERN_REFERENCE_PTR)
        pattern_length = REFERENCE_PTR_LENGTH;
    else if (!(*resp_endptr) && ((uint8_t )temp_start_ptr[index]  >>SHIFT_BITS_REFERENCE_PTR !=
        PATTERN_REFERENCE_PTR ))
    {
        while ((index < data_size) && !(*resp_endptr) && ((uint8_t )temp_start_ptr[index]  >>
            SHIFT_BITS_REFERENCE_PTR != PATTERN_REFERENCE_PTR))
        {
            index++;
            scan_matched_patterns(start_ptr,  size - data_size + index, resp_endptr,
                &pattern_length);
        }
        if (index >= data_size)
            *user_name_len = 0;
        else if ((uint8_t )temp_start_ptr[index]  >> SHIFT_BITS_REFERENCE_PTR ==
            PATTERN_REFERENCE_PTR)
            pattern_length = REFERENCE_PTR_LENGTH;
    }

    /* Add reference pointer bytes */
    if ( index+ pattern_length < data_size)
        *resp_endptr = start_ptr + index+ pattern_length;
    else
        return -1;

    if (*user_name_len > 0)
        return 1;
    else
        return 0;
}

/* Input to this Function is pkt and size
   Processing: 1. Parses Multiple MDNS response packet
               2. Calls the function which scans for pattern to identify the user
               3. Calls the function which does the Username reporting along with the host
  MDNS User Analysis*/
int MdnsServiceDetector::analyze_user(AppIdSession& asd, const Packet* pkt, uint16_t size)
{
    int start_index = 0;
    uint8_t user_name_len = 0;
    uint16_t data_size = size;

    /* Scan for MDNS response, decided on Query value */
    const char* query_val = (const char*)pkt->data + QUERY_OFFSET;
    int query_val_int = (short)(query_val[0]<<SHIFT_BITS  | query_val[1]);
    const char* answers = (const char*)pkt->data + ANSWER_OFFSET;
    int ans_count =  (short)(answers[0]<< SHIFT_BITS | (answers[1] ));

    if ( query_val_int == 0)
    {
        const char* resp_endptr;
        const char* user_original;

        const char* srv_original  = (const char*)pkt->data + RECORD_OFFSET;
        create_match_list(srv_original, size - RECORD_OFFSET);
        const char* end_srv_original  = (const char*)pkt->data + RECORD_OFFSET + data_size;
        for (int processed_ans = 0; processed_ans < ans_count && data_size <= size && size > 0;
            processed_ans++ )
        {
            // Call Decode Reference pointer function if referenced value instead of direct value
            user_name_len = 0;
            int ret_value = reference_pointer(srv_original, &resp_endptr,  &start_index, data_size,
                &user_name_len, size);
            int user_index =0;

            if (ret_value == -1)
                return -1;
            else if (ret_value)
            {
                while (start_index < data_size && (!isprint(srv_original[start_index])  ||
                    srv_original[start_index] == '"' || srv_original[start_index] =='\''))
                {
                    start_index++;
                    user_index++;
                }
                user_name_len -=user_index;

                char user_name[MAX_LENGTH_SERVICE_NAME] = "";
                memcpy(user_name, srv_original + start_index, user_name_len);
                user_name[user_name_len] = '\0';

                user_index =0;
                while (user_index < user_name_len)
                {
                    if (!isprint(user_name[user_index]))
                        return 1;

                    user_index++;
                }

                add_user(asd, user_name, APP_ID_MDNS, true);
                break;
            }

            // Find the  length to Jump to the next response
            if ((resp_endptr  + NEXT_MESSAGE_OFFSET  ) < (srv_original + data_size))
            {
                const uint8_t* data_len_str = (const uint8_t*)(resp_endptr+ LENGTH_OFFSET);
                uint16_t data_len =  (short)( data_len_str[0]<< SHIFT_BITS | ( data_len_str[1] ));
                data_size = data_size - (resp_endptr  + NEXT_MESSAGE_OFFSET + data_len -
                    srv_original);
                /* Check if user name is available in the Domain Name field */
                if (data_size < size)
                {
                    if (memcmp(resp_endptr, SRV_RECORD, sizeof(SRV_RECORD)-1)==0)
                        start_index = SRV_RECORD_OFFSET;
                    else
                        start_index =0;

                    srv_original = resp_endptr  + NEXT_MESSAGE_OFFSET;
                    user_original = (char*)memchr((const uint8_t*)srv_original, PATTERN_USERNAME_1,
                        data_len);

                    if (user_original )
                    {
                        user_name_len = user_original - srv_original - start_index;
                        const char* user_name_bkp = srv_original + start_index;
                        /* Non-Printable characters in the beginning */

                        while (user_index < user_name_len)
                        {
                            if (isprint(user_name_bkp[user_index]))
                                break;

                            user_index++;
                        }

                        int user_printable_index = user_index;
                        /* Non-Printable characters in the between  */

                        while (user_printable_index < user_name_len)
                        {
                            if (!isprint(user_name_bkp [user_printable_index ]))
                                return 0;

                            user_printable_index++;
                        }
                        /* Copy  the user name if available */
                        if (( user_name_len - user_index ) < MAX_LENGTH_SERVICE_NAME )
                        {
                            char user_name[MAX_LENGTH_SERVICE_NAME];
                            memcpy(user_name, user_name_bkp + user_index,
                                user_name_len - user_index);
                            user_name[ user_name_len - user_index ] = '\0';
                            add_user(asd, user_name, APP_ID_MDNS, true);
                            return 1;
                        }
                        else
                            return 0;
                    }

                    srv_original = srv_original +  data_len;
                    if (srv_original > end_srv_original)
                        return 0;
                }
                else
                    return 0;
            }
            else
                return 0;
        }
    }
    else
        return 0;

    return 1;
}

static int mdns_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    MatchedPatterns* cm;
    MatchedPatterns** matches = (MatchedPatterns**)data;
    MdnsPattern* target = (MdnsPattern*)id;
    MatchedPatterns* element;
    MatchedPatterns* prevElement;

    if (patternFreeList)
    {
        cm = patternFreeList;
        patternFreeList = cm->next;
    }
    else
        cm = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));

    cm->mpattern = target;
    cm->match_start_pos = match_end_pos - target->length;
    for (prevElement = nullptr, element = *matches;
        element;
        prevElement = element, element = element->next)
    {
        if (element->match_start_pos > cm->match_start_pos)
            break;
    }

    if (prevElement)
    {
        cm->next = prevElement->next;
        prevElement->next = cm;
    }
    else
    {
        cm->next = *matches;
        *matches = cm;
    }

    return 0;
}

unsigned MdnsServiceDetector::create_match_list(const char* data, uint16_t dataSize)
{
    if (patternList)
        destroy_match_list();

    matcher->find_all((const char*)data, dataSize, mdns_pattern_match, false, (void*)&patternList);

    if (patternList)
        return 1;
    return 0;
}

void MdnsServiceDetector::scan_matched_patterns(const char* dataPtr, uint16_t index, const
    char** resp_endptr,
    int* pattern_length)
{
    while (patternList)
    {
        if (patternList->match_start_pos == index)
        {
            *resp_endptr = dataPtr;
            *pattern_length = patternList->mpattern->length;
            return;
        }

        if (patternList->match_start_pos > index)
            break;

        MatchedPatterns* element = patternList;
        patternList = patternList->next;
        element->next = patternFreeList;
        patternFreeList = element;
    }
    *resp_endptr = nullptr;
    *pattern_length = 0;
}

void MdnsServiceDetector::destroy_match_list()
{
    MatchedPatterns* element;

    while (patternList)
    {
        element = patternList;
        patternList = patternList->next;

        element->next = patternFreeList;
        patternFreeList = element;
    }
}

void MdnsServiceDetector::destory_matcher()
{
    MatchedPatterns* node;

    if (matcher)
        delete matcher;
    matcher = nullptr;

    destroy_match_list();

    while ((node = patternFreeList))
    {
        patternFreeList = node->next;
        snort_free(node);
    }
}

