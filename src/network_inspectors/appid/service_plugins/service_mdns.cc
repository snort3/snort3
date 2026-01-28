//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
#include "pub_sub/deviceinfo_events.h"
#include "appid_inspector.h"
#include <vector>
#include <string>
#include <utility>
#include <map>
#include <set>

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
#define DNS_COMPRESSION_PTR_SKIP  2
#define DNS_LABEL_LENGTH_SKIP  1
#define DNS_QUESTION_FIXED_SIZE  4
#define DNS_RECORD_HEADER_SIZE  10
#define TXT_RECORD_TYPE  0x0010
#define DNS_COMPRESSION_MASK  0xC0
#define DNS_NULL_TERMINATOR  0x00
#define DNS_COMPRESSION_OFFSET_MASK  0x3F
#define DNS_RDLENGTH_SIZE  2

enum MDNSState
{
    MDNS_STATE_CONNECTION,
    MDNS_STATE_CONNECTION_ERROR
};

class ServiceMDNSData : public AppIdFlowData
{
public:
    ~ServiceMDNSData() override = default;

    MDNSState state = MDNS_STATE_CONNECTION;
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

    for (unsigned i = 0; i < sizeof(patterns) / sizeof(*patterns); i++)
        matcher.add((const char*)patterns[i].pattern, patterns[i].length, &patterns[i]);
    matcher.prep();

    handler->register_detector(name, this, proto);
}

void MdnsServiceDetector::do_custom_reload()
{
    matcher.reload();
}

int MdnsServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceMDNSData* fd = static_cast<ServiceMDNSData*>(data_get(args.asd));
    if (!fd)
    {
        fd = new ServiceMDNSData();
        data_add(args.asd, fd);
    }

    if (args.pkt->ptrs.dp == MDNS_PORT || args.pkt->ptrs.sp == MDNS_PORT )
    {
        int ret_val = validate_reply(args.data, args.size);
        if (ret_val == 1)
        {
            if (args.asd.get_odp_ctxt().mdns_user_reporting)
            {
                MatchedPatterns* pattern_list = nullptr;
                analyze_user(args.asd, args.pkt, args.size, args.change_bits, pattern_list);
                destroy_match_list(pattern_list);
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
    return add_service(args.change_bits, args.asd, args.pkt, args.dir, APP_ID_MDNS);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

int MdnsServiceDetector::validate_reply(const uint8_t* data, uint16_t size)
{
    int ret_val;

    // Minimum MDNS packet size for header fields
    // (query_val, ans_count, srv_original)
    if (size < RECORD_OFFSET)
        return 0;

    /* Check for the pattern match*/
    if (memcmp(data, MDNS_PATTERN1, sizeof(MDNS_PATTERN1)-1) == 0)
        ret_val = 1;
    else if (memcmp(data, MDNS_PATTERN2,  sizeof(MDNS_PATTERN2)-1) == 0)
        ret_val = 1;
    else if (memcmp(data,MDNS_PATTERN3, sizeof(MDNS_PATTERN3)-1) == 0)
        ret_val = 1;
    else if (memcmp(data,MDNS_PATTERN4, sizeof(MDNS_PATTERN4)-1) == 0)
        ret_val = 1;
    else
        ret_val = 0;

    return ret_val;
}

/* Input to this function is start_ptr and data_size.
   Output is resp_endptr, start_index and user_name_len
   Returns 0 or 1 for successful/unsuccessful hit for pattern '@'
   Returns -1 for invalid address pointer or past the data_size */
int MdnsServiceDetector::reference_pointer(const char* start_ptr, const char* end_pkt,
   const char** resp_endptr, int* start_index, uint16_t data_size,
   uint8_t* user_name_len, unsigned size, MatchedPatterns*& pattern_list)
{
    int index = 0;
    int pattern_length = 0;

    while ((start_ptr + index) < end_pkt && (start_ptr[index] == ' '))
        index++;

    if ((start_ptr + index) >= end_pkt)
        return -1;
    *start_index = index;

    const char* temp_start_ptr = start_ptr + index;

    int temp_index = 0;

    scan_matched_patterns(start_ptr, size - data_size + index, resp_endptr, &pattern_length, pattern_list);

    while ((temp_start_ptr + temp_index) < end_pkt && !(*resp_endptr) &&
            ((uint8_t)temp_start_ptr[temp_index] >> SHIFT_BITS_REFERENCE_PTR != PATTERN_REFERENCE_PTR))
    {
        if (temp_start_ptr[temp_index] == PATTERN_USERNAME_1)
        {
            *user_name_len = temp_index;
            temp_index++;
            break;
        }
        temp_index++;
        scan_matched_patterns(start_ptr, size - data_size + index + temp_index, resp_endptr, &pattern_length, pattern_list);
       }

    if ((temp_start_ptr + temp_index) >= end_pkt)
        *user_name_len = 0;
    else if ((uint8_t)temp_start_ptr[temp_index] >> SHIFT_BITS_REFERENCE_PTR == PATTERN_REFERENCE_PTR)
        pattern_length = REFERENCE_PTR_LENGTH;
    else if (!(*resp_endptr) &&
            ((uint8_t)temp_start_ptr[temp_index] >> SHIFT_BITS_REFERENCE_PTR != PATTERN_REFERENCE_PTR))
    {
        while ((temp_start_ptr + temp_index) < end_pkt && !(*resp_endptr) &&
                ((uint8_t)temp_start_ptr[temp_index] >> SHIFT_BITS_REFERENCE_PTR != PATTERN_REFERENCE_PTR))
        {
            temp_index++;
            scan_matched_patterns(start_ptr, size - data_size + index + temp_index, resp_endptr, &pattern_length, pattern_list);
        }

        if ((temp_start_ptr + temp_index) >= end_pkt)
            *user_name_len = 0;
        else if ((uint8_t)temp_start_ptr[temp_index] >> SHIFT_BITS_REFERENCE_PTR == PATTERN_REFERENCE_PTR)
            pattern_length = REFERENCE_PTR_LENGTH;
    }

    const char* name_parser = temp_start_ptr + temp_index;
    
    while (name_parser < end_pkt)
    {
        if (((unsigned char)*name_parser & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK)
        {
            name_parser += DNS_COMPRESSION_PTR_SKIP;
            break;
        }
        else if (*name_parser == DNS_NULL_TERMINATOR)
        {
            name_parser += DNS_LABEL_LENGTH_SKIP;
            break;
        }
        else
        {
            uint8_t label_len = (unsigned char)*name_parser;
            if (name_parser + DNS_LABEL_LENGTH_SKIP + label_len > end_pkt)
                return -1;
            name_parser += DNS_LABEL_LENGTH_SKIP + label_len;
        }
    }

    if (name_parser < end_pkt)
    {
        *resp_endptr = name_parser;
    }
    else
    {
        return -1;
    }


    if (*user_name_len > 0)
        return 1;
    else
        return 0;
}

static bool is_printable_string(const std::string& str)
{
    return std::all_of(str.begin(), str.end(), [](unsigned char c) {
        return std::isprint(c);
    }) && !str.empty();
}

static std::string clean_mdns_string(const std::string& str)
{
    std::string clean;
    for (char c : str)
    {
        if (static_cast<unsigned char>(c) < 128 && std::isprint(c))
            clean += c;
    }
    return clean;
}

void MdnsServiceDetector::process_txt_record(const snort::Packet* pkt, const char* srv_original, 
    const char* rdata_start, uint16_t data_len, const char* packet_end, 
    std::string& protocol_type, std::string& device_name,
    std::vector<std::pair<std::string, std::string>>& kv_pairs)
{
    const char* dns_name_start = srv_original;
    const char* name_parser = dns_name_start;
    bool first_label = true;
    std::set<const char*> visited_ptrs;

    while (name_parser < packet_end)
    {
        if (((unsigned char)*name_parser & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK)
        {
            if (name_parser + 1 >= packet_end)
                break;
            uint16_t offset = ((name_parser[0] & DNS_COMPRESSION_OFFSET_MASK) << SHIFT_BITS) | (unsigned char)name_parser[1];
            
            if (offset >= (packet_end - (const char*)pkt->data) || offset < RECORD_OFFSET)
            {
                break;
            }

            const char* compressed_ptr = (const char*)pkt->data + offset;
            if (compressed_ptr < packet_end and compressed_ptr >= (const char*)pkt->data)
            {
                if (visited_ptrs.find(compressed_ptr) != visited_ptrs.end())
                {
                    break;
                }
                visited_ptrs.insert(compressed_ptr);
                name_parser = compressed_ptr;
                continue;
            }
            else
                break;
        }
        else if (*name_parser == DNS_NULL_TERMINATOR)
            break;
        else
        {
            uint8_t label_len = (unsigned char)*name_parser;
            name_parser += DNS_LABEL_LENGTH_SKIP;
            if (name_parser + label_len > packet_end)
                break;

            std::string label(name_parser, label_len);
            
            if (first_label)
            {
                device_name = std::move(label);
                
                size_t at_pos = device_name.find(PATTERN_USERNAME_1);
                if (at_pos != std::string::npos and at_pos > 0)
                {
                    device_name = device_name.substr(at_pos + DNS_LABEL_LENGTH_SKIP);
                }

                size_t dot_pos = device_name.find('.');
                if (dot_pos != std::string::npos and dot_pos > 0)
                {
                    protocol_type = device_name.substr(dot_pos + DNS_LABEL_LENGTH_SKIP);
                    device_name = device_name.substr(0, dot_pos);
                }

                if (!is_printable_string(device_name))
                {
                    device_name.clear();
                }
                else
                {
                    device_name = clean_mdns_string(device_name);
                }
                
                first_label = false;
            }
            else
            {
                if (!protocol_type.empty())
                    protocol_type += ".";
                protocol_type += label;
            }
            
            name_parser += label_len;
        }
    }

    const uint8_t* txt_data = (const uint8_t*)rdata_start;
    if (rdata_start + data_len > packet_end)
    {
        return;
    }
    const uint8_t* txt_end = txt_data + data_len;
    
    while (txt_data < txt_end)
    {
        uint8_t txt_len = *txt_data++;
        
        if (txt_len == 0 || txt_data + txt_len > txt_end)
        {
            break;
        }
        
        std::string txt_string((const char*)txt_data, txt_len);
        txt_data += txt_len;

        if (txt_string.empty())
            continue;

        size_t equals_pos = txt_string.find('=');
        if (equals_pos != std::string::npos and equals_pos > 0)
        {
            std::string key = txt_string.substr(0, equals_pos);
            std::string value = txt_string.substr(equals_pos + 1);

            if (is_printable_string(key) && (value.empty() || is_printable_string(value)))
            {
                key = clean_mdns_string(key);
                value = clean_mdns_string(value);
                kv_pairs.emplace_back(key, value);
            }
        }
        else
        {
            if (is_printable_string(txt_string))
            {
                std::string clean_key = clean_mdns_string(txt_string);
                kv_pairs.emplace_back(clean_key, "");
            }
        }
    }
}

/* Input to this Function is pkt and size
   Processing: 1. Parses Multiple MDNS response packet
               2. Calls the function which scans for pattern to identify the user
               3. Calls the function which does the Username reporting along with the host
  MDNS User Analysis*/
int MdnsServiceDetector::analyze_user(AppIdSession& asd, const Packet* pkt, uint16_t size,
    AppidChangeBits& change_bits, MatchedPatterns*& pattern_list)
{
    int start_index = 0;
    uint16_t data_size = size;

    /* Scan for MDNS response, decided on Query value */
    const char* query_val = (const char*)pkt->data + QUERY_OFFSET;
    int query_val_int = (short)(query_val[0]<<SHIFT_BITS  | query_val[1]);
    const char* answers = (const char*)pkt->data + ANSWER_OFFSET;
    int ans_count =  (short)(answers[0]<< SHIFT_BITS | (answers[1] ));
    int authority_count = (short)(answers[2]<< SHIFT_BITS | (answers[3] ));
    int additional_count = (short)(answers[4]<< SHIFT_BITS | (answers[5] ));
    std::map<std::pair<std::string, std::string>, std::vector<std::pair<std::string, std::string>>> device_info_map;


    if ( query_val_int == 0)
    {
        const char* resp_endptr;
        const char* user_original;

        const char* srv_original  = (const char*)pkt->data + RECORD_OFFSET;
        pattern_list = create_match_list(srv_original, size - RECORD_OFFSET);
        const char* end_srv_original  = (const char*)pkt->data + RECORD_OFFSET + data_size;
        int total_records = ans_count + authority_count + additional_count;
        for (int processed_records = 0; processed_records < total_records && data_size <= size;
            processed_records++ )
        {
            // Call Decode Reference pointer function if referenced value instead of direct value
            uint8_t user_name_len = 0;
            const char* packet_end = (const char*)pkt->data + size;
            int ret_value = reference_pointer(srv_original, packet_end, &resp_endptr, &start_index,
                                             data_size, &user_name_len, size, pattern_list);
            int user_index =0;

            if (ret_value == -1)
                return -1;
            else if (ret_value)
            {
                while ((srv_original + start_index) < packet_end && start_index < data_size &&
                       (!isprint(srv_original[start_index]) ||
                        srv_original[start_index] == '"' || srv_original[start_index] =='\''))
                {
                    start_index++;
                    user_index++;
                }

                if (user_index <= user_name_len)
                    user_name_len -= user_index;
                 else
                    user_name_len = 0;

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

                add_user(asd, user_name, APP_ID_MDNS, true, change_bits);
                break;
            }

            // Find the  length to Jump to the next response
            if ((resp_endptr  + NEXT_MESSAGE_OFFSET) < packet_end)
            {
                if (((unsigned char)resp_endptr[0] & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK)
                    resp_endptr += DNS_COMPRESSION_PTR_SKIP;
                uint16_t record_type = ((uint8_t)resp_endptr[0] << SHIFT_BITS) | (uint8_t)resp_endptr[1];
                
                const uint8_t* rdlength_ptr = (const uint8_t*)(resp_endptr + LENGTH_OFFSET);
                if (rdlength_ptr + DNS_RDLENGTH_SIZE > (const uint8_t*)packet_end)
                    return -1;

                uint16_t data_len = (rdlength_ptr[0] << SHIFT_BITS) | rdlength_ptr[1];

                const char* rdata_start = resp_endptr + NEXT_MESSAGE_OFFSET;
                if (rdata_start + data_len > packet_end)
                    return -1;

                if (record_type == TXT_RECORD_TYPE and data_len > 0 and asd.get_odp_ctxt().mdns_deviceinfo)
                {
                    std::string protocol_type, device_name;
                    std::vector<std::pair<std::string, std::string>> kv_pairs;
                    const char* dns_name_ptr = srv_original;
                    process_txt_record(pkt, dns_name_ptr, rdata_start, data_len, packet_end,
                                     protocol_type, device_name, kv_pairs);
                    if (!protocol_type.empty() || !device_name.empty())
                    {
                        auto device_key = std::make_pair(protocol_type, device_name);
                        device_info_map[device_key] = std::move(kv_pairs);
                    }
                }

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
                    user_original = (const char*)memchr((const uint8_t*)srv_original, PATTERN_USERNAME_1,
                        data_len);

                    if ( user_original )
                    {
                        user_name_len = user_original - srv_original - start_index;
                        const char* user_name_bkp = srv_original + start_index;

                        if (user_name_bkp + user_name_len > packet_end)
                            return 0;

                        /* Non-Printable characters in the beginning */
                        while (user_index < user_name_len && (user_name_bkp + user_index) < packet_end)
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
                            add_user(asd, user_name, APP_ID_MDNS, true, change_bits);
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

    if (!device_info_map.empty() and asd.get_odp_ctxt().mdns_deviceinfo)
    {
        DeviceInfoEvent event(pkt, device_info_map);
        DataBus::publish(DataBus::get_id(deviceinfo_pub_key), DeviceInfoEventIds::DEVICEINFO, event);
    }
    return 1;
}

static int mdns_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    MatchedPatterns* cm;
    MatchedPatterns** matches = (MatchedPatterns**)data;
    MdnsPattern* target = (MdnsPattern*)id;
    MatchedPatterns* element;
    MatchedPatterns* prevElement;

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

MatchedPatterns* MdnsServiceDetector::create_match_list(const char* data, uint16_t dataSize)
{
    MatchedPatterns* pattern_list = nullptr;
    matcher.find_all((const char*)data, dataSize, mdns_pattern_match, false, (void*)&pattern_list);

    return pattern_list;
}

void MdnsServiceDetector::scan_matched_patterns(const char* dataPtr, uint16_t index, const
    char** resp_endptr, int* pattern_length, MatchedPatterns*& pattern_list)
{
    while (pattern_list)
    {
        if (pattern_list->match_start_pos == index)
        {
            *resp_endptr = dataPtr;
            *pattern_length = pattern_list->mpattern->length;
            return;
        }

        if (pattern_list->match_start_pos > index)
            break;

        MatchedPatterns* element = pattern_list;
        pattern_list = pattern_list->next;
        snort_free(element);
    }
    *resp_endptr = nullptr;
    *pattern_length = 0;
}

void MdnsServiceDetector::destroy_match_list(MatchedPatterns*& pattern_list)
{
    while (pattern_list)
    {
        MatchedPatterns* element = pattern_list;
        pattern_list = pattern_list->next;

        snort_free(element);
    }
}
