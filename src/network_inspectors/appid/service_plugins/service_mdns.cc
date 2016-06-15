//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "service_mdns.h"

#include "search_engines/search_tool.h"
#include "client_plugins/client_app_base.h"
#include "detector_plugins/http_url_patterns.h"
#include "detector_plugins/detector_http.h"
#include "util/common_util.h"
#include "appid_config.h"
#include "appid_flow_data.h"
#include "fw_appid.h"
#include "http_common.h"
#include "lua_detector_api.h"
#include "service_api.h"
#include "service_base.h"
#include "service_ssl.h"

#include "main/snort_debug.h"
#include "utils/util.h"

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
    int index;
    MatchedPatterns* next;
};

struct MdnsConfig
{
    SearchTool* mdnsMatcher;
    MatchedPatterns* patternList;
};

static int MDNS_init(const IniServiceAPI* const init_api);
static int ReferencePointer(const char* start_ptr,const char** resp_endptr,   int* start_index,
    uint16_t data_size, uint8_t* user_name_len, unsigned offset, const AppIdConfig* pConfig);
static int MDNS_validate(ServiceValidationArgs* args);
static int mdnsMatcherCreate(AppIdConfig* pConfig);
static void mdnsMatcherDestroy(AppIdConfig* pConfig);
static unsigned mdnsMatchListCreate(const char* data, uint16_t dataSize, const
    AppIdConfig* pConfig);
static void mdnsMatchListFind(const char* dataPtr, uint16_t index, const char** resp_endptr,
    int* pattern_length, const AppIdConfig* pConfig);
static void mdnsMatchListDestroy(const AppIdConfig* pConfig);
static void MDNS_clean(const CleanServiceAPI* const clean_api);

static RNAServiceElement svc_element =
{
    nullptr,
    &MDNS_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "MDNS"
};

static RNAServiceValidationPort pp[] =
{
    { &MDNS_validate, 5353, IpProtocol::UDP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule mdns_service_mod =
{
    "MDNS",
    &MDNS_init,
    pp,
    nullptr,
    nullptr,
    0,
    MDNS_clean,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_MDNS, APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static int MDNS_init(const IniServiceAPI* const init_api)
{
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&MDNS_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    mdnsMatcherCreate(init_api->pAppidConfig);
    return 0;
}

static int MDNS_validate_reply(const uint8_t* data, uint16_t size)
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
static int ReferencePointer(const char* start_ptr, const char** resp_endptr,   int* start_index,
    uint16_t data_size, uint8_t* user_name_len, unsigned size, const AppIdConfig* pConfig)
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

    mdnsMatchListFind(start_ptr, size - data_size + index, resp_endptr, &pattern_length, pConfig);
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
        mdnsMatchListFind(start_ptr, size - data_size + index, resp_endptr, &pattern_length,
            pConfig);
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
            mdnsMatchListFind(start_ptr,  size - data_size + index, resp_endptr, &pattern_length,
                pConfig);
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
static int MDNSUserAnalyser(AppIdData* flowp, const Packet* pkt, uint16_t size, const
    AppIdConfig* pConfig)
{
    const char* query_val;
    const char* answers;
    char user_name[MAX_LENGTH_SERVICE_NAME] = "";
    char* user_name_bkp = nullptr;
    const char* resp_endptr;
    const char* srv_original;
    const char* end_srv_original;
    const char* user_original;
    int query_val_int;
    int ans_count = 0;
    int start_index =0;
    int processed_ans =0;
    uint16_t data_len = 0;
    uint8_t* data_len_str;
    uint8_t user_name_len = 0;
    uint16_t data_size = size;

    /* Scan for MDNS response, decided on Query value */
    query_val = (char*)pkt->data + QUERY_OFFSET;
    query_val_int = (short)(query_val[0]<<SHIFT_BITS  | query_val[1]);
    answers = (char*)pkt->data + ANSWER_OFFSET;
    ans_count =  (short)(answers[0]<< SHIFT_BITS | (answers[1] ));

    if ( query_val_int ==0)
    {
        srv_original  = (char*)pkt->data + RECORD_OFFSET;
        mdnsMatchListCreate(srv_original, size-RECORD_OFFSET, pConfig);
        end_srv_original  = (char*)pkt->data + RECORD_OFFSET+data_size;
        for (processed_ans =0; processed_ans< ans_count && data_size <= size && size > 0;
            processed_ans++ )
        {
            /* Call Decode Reference pointer function if referenced value instead of direct value
               */
            user_name_len = 0;
            int ret_value = ReferencePointer(srv_original, &resp_endptr,  &start_index, data_size,
                &user_name_len, size, pConfig);
            int user_index =0;
            int user_printable_index =0;

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

                memcpy(user_name, srv_original+start_index, user_name_len);
                user_name[user_name_len] = '\0';

                user_index =0;
                while (user_index < user_name_len)
                {
                    if (!isprint(user_name[user_index]))
                        return 1;

                    user_index++;
                }

                AppIdAddUser(flowp, user_name, APP_ID_MDNS, 1);
                break;
            }
            /* Find the  length to Jump to the next response */

            if ((resp_endptr  + NEXT_MESSAGE_OFFSET  ) < (srv_original + data_size))
            {
                data_len_str = (uint8_t*)(resp_endptr+ LENGTH_OFFSET);
                data_len =  (short)( data_len_str[0]<< SHIFT_BITS | ( data_len_str[1] ));
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
                        user_name_bkp = (char*)(srv_original + start_index);
                        /* Non-Printable characters in the begining */

                        while (user_index < user_name_len)
                        {
                            if (isprint(user_name_bkp[user_index]))
                                break;

                            user_index++;
                        }

                        user_printable_index = user_index;
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
                            memcpy(user_name, user_name_bkp + user_index, user_name_len -
                                user_index);
                            user_name[ user_name_len - user_index ] = '\0';
                            AppIdAddUser(flowp, user_name, APP_ID_MDNS, 1);
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

static int MDNS_validate(ServiceValidationArgs* args)
{
    ServiceMDNSData* fd;
    int ret_val;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    uint16_t size = args->size;

    fd = (ServiceMDNSData*)mdns_service_mod.api->data_get(flowp, mdns_service_mod.flow_data_index);
    if (!fd)
    {
        fd = (ServiceMDNSData*)snort_calloc(sizeof(ServiceMDNSData));
        mdns_service_mod.api->data_add(flowp, fd, mdns_service_mod.flow_data_index, &snort_free);
        fd->state = MDNS_STATE_CONNECTION;
    }

    if (pkt->ptrs.dp == MDNS_PORT || pkt->ptrs.sp == MDNS_PORT )
    {
        ret_val = MDNS_validate_reply(data, size);
        if (ret_val == 1)
        {
            if (pAppidActiveConfig->mod_config->mdns_user_reporting)
            {
                MDNSUserAnalyser(flowp, pkt, size, args->pConfig);
                mdnsMatchListDestroy(args->pConfig);
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
    mdns_service_mod.api->add_service(flowp, pkt, args->dir, &svc_element,
        APP_ID_MDNS, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    mdns_service_mod.api->fail_service(flowp, pkt, args->dir, &svc_element,
        mdns_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

static MatchedPatterns* patternFreeList;

static MdnsPattern patterns[] =
{
    { (uint8_t*)PATTERN_STR_LOCAL_1, sizeof(PATTERN_STR_LOCAL_1) },
    { (uint8_t*)PATTERN_STR_LOCAL_2, sizeof(PATTERN_STR_LOCAL_2) },
    { (uint8_t*)PATTERN_STR_ARPA_1, sizeof(PATTERN_STR_ARPA_1) },
    { (uint8_t*)PATTERN_STR_ARPA_2, sizeof(PATTERN_STR_ARPA_2) },
};

static int mdnsMatcherCreate(AppIdConfig* pConfig)
{
    MdnsConfig* pMdnsConfig = (MdnsConfig*)snort_calloc(sizeof(MdnsConfig));

    if (!(pMdnsConfig->mdnsMatcher = new SearchTool("ac_full")))
    {
        snort_free(pMdnsConfig);
        return 0;
    }

    for (unsigned i = 0; i < sizeof(patterns) / sizeof(*patterns); i++)
        pMdnsConfig->mdnsMatcher->add(
            (char*)patterns[i].pattern, patterns[i].length, &patterns[i]);

    pMdnsConfig->mdnsMatcher->prep();
    pConfig->add_generic_config_element(svc_element.name, pMdnsConfig);
    return 1;
}

static void mdnsMatcherDestroy(AppIdConfig* pConfig)
{
    MdnsConfig* pMdnsConfig = (MdnsConfig*)pConfig->find_generic_config_element(svc_element.name);
    MatchedPatterns* node;
    if (pMdnsConfig->mdnsMatcher)
        delete pMdnsConfig->mdnsMatcher;
    pMdnsConfig->mdnsMatcher = nullptr;

    mdnsMatchListDestroy(pConfig);

    while ((node = patternFreeList))
    {
        patternFreeList = node->next;
        snort_free(node);
    }
    snort_free(pMdnsConfig);
    pConfig->remove_generic_config_element(svc_element.name);
}

static int mdns_pattern_match(void* id, void*, int index, void* data, void*)
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
    cm->index = index;
    for (prevElement = nullptr, element = *matches;
        element;
        prevElement = element, element = element->next)
    {
        if (element->index > index)
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

static unsigned mdnsMatchListCreate(const char* data, uint16_t dataSize, const
    AppIdConfig* pConfig)
{
    MdnsConfig* pMdnsConfig = (MdnsConfig*)((AppIdConfig*)pConfig)->find_generic_config_element(
        svc_element.name);

    if (pMdnsConfig->patternList)
        mdnsMatchListDestroy(pConfig);

    pMdnsConfig->mdnsMatcher->find_all(
        (char*)data, dataSize, mdns_pattern_match, false, (void*)&pMdnsConfig->patternList);

    if (pMdnsConfig->patternList)
        return 1;
    return 0;
}

static void mdnsMatchListFind(const char* dataPtr, uint16_t index, const char** resp_endptr,
    int* pattern_length, const AppIdConfig* pConfig)
{
    MdnsConfig* pMdnsConfig = (MdnsConfig*)((AppIdConfig*)pConfig)->find_generic_config_element(
        svc_element.name);

    while (pMdnsConfig->patternList)
    {
        if (pMdnsConfig->patternList->index == index)
        {
            *resp_endptr = dataPtr+pMdnsConfig->patternList->index-index;
            *pattern_length = pMdnsConfig->patternList->mpattern->length;
            return;
        }
        if (pMdnsConfig->patternList->index > index)
            break;
        MatchedPatterns* element;
        element = pMdnsConfig->patternList;
        pMdnsConfig->patternList = pMdnsConfig->patternList->next;

        element->next = patternFreeList;
        patternFreeList = element;
    }
    *resp_endptr = nullptr;
    *pattern_length = 0;
}

static void mdnsMatchListDestroy(const AppIdConfig* pConfig)
{
    MatchedPatterns* element;

    MdnsConfig* pMdnsConfig = (MdnsConfig*)((AppIdConfig*)pConfig)->find_generic_config_element(
        svc_element.name);
    while (pMdnsConfig->patternList)
    {
        element = pMdnsConfig->patternList;
        pMdnsConfig->patternList = pMdnsConfig->patternList->next;

        element->next = patternFreeList;
        patternFreeList = element;
    }
}

static void MDNS_clean(const CleanServiceAPI* const clean_api)
{
    mdnsMatcherDestroy(clean_api->pAppidConfig);
}

