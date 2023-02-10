//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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
// reputation_parse.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "reputation_parse.h"

#include <netinet/in.h>

#include <cassert>
#include <climits>
#include <fstream>
#include <limits>

#include "main/snort_config.h"
#include "log/messages.h"
#include "parser/config_file.h"
#include "sfip/sf_cidr.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "reputation_config.h"
#include "reputation_inspect.h"

using namespace snort;
using namespace std;

enum
{
    IP_INSERT_SUCCESS = 0,
    IP_INVALID,
    IP_INSERT_FAILURE,
    IP_INSERT_DUPLICATE,
    IP_MEM_ALLOC_FAILURE
};

#define MAX_ADDR_LINE_LENGTH    8192

#define MANIFEST_SEPARATORS         ",\r\n"
#define MIN_MANIFEST_COLUMNS         3

static char block_info[] = "blocklist";
static char allow_info[] = "allowlist";
static char monitor_info[] = "monitorlist";

// Support backward compatibility
#define WHITE_TYPE_KEYWORD       "white"

#define TRUST_TYPE_KEYWORD       "trust"
#define BLOCK_TYPE_KEYWORD       "block"
#define MONITOR_TYPE_KEYWORD     "monitor"

#define UNKNOWN_LIST    0
#define MONITOR_LIST    1
#define BLOCK_LIST      2
#define ALLOW_LIST      3

#define MAX_MSGS_TO_PRINT      20

unsigned long total_duplicates;
unsigned long total_invalids;

int totalNumEntries = 0;

static uint32_t estimate_size(uint32_t num_entries, uint32_t memcap)
{
    uint64_t size;
    uint64_t size_from_entries;

    /*memcap value is in Megabytes*/
    size = (uint64_t)memcap << 20;

    if (size > std::numeric_limits<uint32_t>::max())
        size = std::numeric_limits<uint32_t>::max();

    /*Worst case,  15k ~ 2^14 per entry, plus one Megabytes for empty table*/
    if (num_entries > ((std::numeric_limits<uint32_t>::max() - (1 << 20))>> 15))
        size_from_entries = std::numeric_limits<uint32_t>::max();
    else
        size_from_entries = (num_entries << 15) + (1 << 20);

    if (size > size_from_entries)
    {
        size = size_from_entries;
    }

    return (uint32_t)size;
}

static inline IPrepInfo* get_last_index(IPrepInfo* rep_info, uint8_t* base, int* last_index)
{
    int i;

    assert(rep_info);

    /* Move to the end of current info*/
    while (rep_info->next)
    {
        rep_info =  (IPrepInfo*)&base[rep_info->next];
    }

    for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
    {
        if (!rep_info->list_indexes[i])
            break;
    }

    if (i > 0)
    {
        *last_index = i-1;
        return rep_info;
    }
    else
    {
        return nullptr;
    }
}

int ReputationParser::duplicate_info(IPrepInfo* dest_info, IPrepInfo* current_info, uint8_t* base)
{
    int bytes_allocated = 0;

    while (current_info)
    {
        INFO next_info;
        *dest_info = *current_info;
        if (!current_info->next)
            break;
        next_info = table.segment_snort_calloc(1, sizeof(IPrepInfo));
        if (!next_info)
        {
            dest_info->next = 0;
            return -1;
        }
        else
        {
            dest_info->next = next_info;
        }
        bytes_allocated += sizeof(IPrepInfo);
        current_info =  (IPrepInfo*)&base[current_info->next];
        dest_info =  (IPrepInfo*)&base[next_info];
    }

    return bytes_allocated;
}

int64_t ReputationParser::update_entry_info_impl(INFO* current, INFO new_entry, SaveDest save_dest, uint8_t* base)
{
    IPrepInfo* current_info;
    IPrepInfo* new_info;
    IPrepInfo* dest_info;
    IPrepInfo* last_info;
    int64_t bytes_allocated = 0;
    int i;
    char new_index;

    if (!(*current))
    {
        /* Copy the data to segment memory*/
        *current = table.segment_snort_calloc(1, sizeof(IPrepInfo));
        if (!(*current))
        {
            return -1;
        }
        bytes_allocated = sizeof(IPrepInfo);
    }

    if (*current == new_entry)
        return bytes_allocated;

    current_info = (IPrepInfo*)&base[*current];
    new_info = (IPrepInfo*)&base[new_entry];

    /*The latest information is always the last entry
     */
    last_info = get_last_index(new_info, base, &i);

    if (!last_info)
    {
        return bytes_allocated;
    }
    new_index = last_info->list_indexes[i++];

    if (SAVE_TO_NEW == save_dest)
    {
        int bytes_duplicated;

        /* When updating new entry, current information should be reserved
         * because current information is inherited from parent
         */
        if ((bytes_duplicated = duplicate_info(new_info, current_info, base)) < 0)
            return -1;
        else
            bytes_allocated += bytes_duplicated;

        dest_info = new_info;
    }
    else
    {
        dest_info = current_info;
    }

    /* Add the new list information to the end
     * This way, the order of list information is preserved.
     * The first one always has the highest priority,
     * because it is checked first during lookup.
     */

    while (dest_info->next)
    {
        dest_info =  (IPrepInfo*)&base[dest_info->next];
    }

    for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
    {
        if (!dest_info->list_indexes[i])
            break;
        else if (dest_info->list_indexes[i] == new_index)
        {
            return bytes_allocated;
        }
    }

    if (i < NUM_INDEX_PER_ENTRY)
    {
        dest_info->list_indexes[i] = new_index;
    }
    else
    {
        IPrepInfo* next_info;
        MEM_OFFSET ipInfo_ptr = table.segment_snort_calloc(1, sizeof(IPrepInfo));
        if (!ipInfo_ptr)
            return -1;
        dest_info->next = ipInfo_ptr;
        next_info = (IPrepInfo*)&base[dest_info->next];
        next_info->list_indexes[0] = new_index;
        bytes_allocated += sizeof(IPrepInfo);
    }

    return bytes_allocated;
}

int64_t ReputationParser::update_entry_info(INFO* current, INFO new_entry, SaveDest save_dest, uint8_t* base,
    void* data)
{
    assert(data);
    ReputationParser* parser = static_cast<ReputationParser*>(data);
    return parser->update_entry_info_impl(current, new_entry, save_dest, base);
}

int ReputationParser::add_ip(SfCidr* ip_addr,INFO info_ptr, const ReputationConfig& config)
{
    /*This variable is used to check whether a more generic address
     * overrides specific address
     */
    uint32_t usage_before;
    uint32_t usage_after;

    usage_before = table.sfrt_flat_usage();

    int final_ret = IP_INSERT_SUCCESS;
    /*Check whether the same or more generic address is already in the table*/
    if (nullptr != table.sfrt_flat_lookup(ip_addr->get_addr()))
        final_ret = IP_INSERT_DUPLICATE;

    int ret = table.sfrt_flat_insert(ip_addr, (unsigned char)ip_addr->get_bits(), info_ptr, RT_FAVOR_ALL,
        &update_entry_info, this);

    if (RT_SUCCESS == ret)
        totalNumEntries++;
    else if (MEM_ALLOC_FAILURE == ret)
        final_ret = IP_MEM_ALLOC_FAILURE;
    else
        final_ret = IP_INSERT_FAILURE;

    usage_after = table.sfrt_flat_usage();
    /*Compare in the same scale*/
    if (usage_after > (config.memcap << 20))
        final_ret = IP_MEM_ALLOC_FAILURE;
    /*Check whether there a more specific address will be overridden*/
    if (usage_before > usage_after )
        final_ret = IP_INSERT_DUPLICATE;

    return final_ret;
}

// FIXIT-L X Remove this or at least move it to SfCidr?
static int snort_pton_address(char const* src, SfCidr* dest)
{
    unsigned char _temp[sizeof(struct in6_addr)];

    if ( inet_pton(AF_INET, src, _temp) == 1 )
        dest->set(_temp, AF_INET);
    else if ( inet_pton(AF_INET6, src, _temp) == 1 )
        dest->set(_temp, AF_INET6);
    else
        return 0;

    return 1;
}

// FIXIT-L X Remove this or at least move it to SfCidr?
#define isident(x) (isxdigit((x)) || (x) == ':' || (x) == '.')
static int snort_pton(char const* src, SfCidr* dest)
{
    char ipbuf[INET6_ADDRSTRLEN];
    char cidrbuf[sizeof("128")];
    char* out = ipbuf;
    enum { BEGIN, IP, CIDR1, CIDR2, END, INVALID } state = BEGIN;

    memset(ipbuf, '\0', sizeof(ipbuf));
    memset(cidrbuf, '\0', sizeof(cidrbuf));

    while ( *src )
    {
        char ch = *src;

        //printf("State:%d; C:%x; P:%p\n", state, ch, src );
        src += 1;

        switch ( state )
        {
        // Scan for beginning of IP address
        case BEGIN:
            if ( isident((int)ch) )
            {
                // Set the first ipbuff byte and change state
                *out++ = ch;
                state = IP;
            }
            else if ( !isspace((int)ch) )
            {
                state = INVALID;
            }
            break;

        // Fill in ipbuf with ip identifier characters
        // Move to CIDR1 if a cidr divider (i.e., '/') is found.
        case IP:
            if ( isident((int)ch) && (out - ipbuf + 1) < (int)sizeof(ipbuf) )
            {
                *out++ = ch;
            }
            else if ( ch == '/' )
            {
                state = CIDR1;
            }
            else if ( isspace((int)ch) )
            {
                state = END;
            }
            else
            {
                state = INVALID;
            }
            break;

        // First cidr digit
        case CIDR1:
            if ( !isdigit((int)ch) )
            {
                state = INVALID;
            }
            else
            {
                // Set output to the cidrbuf buffer
                out = cidrbuf;
                *out++ = ch;
                state = CIDR2;
            }
            break;

        // Consume any addition digits for cidrbuf
        case CIDR2:
            if ( isdigit((int)ch) && (out - cidrbuf + 1) < (int)sizeof(cidrbuf) )
            {
                *out++ = ch;
            }
            else if ( isspace((int)ch) )
            {
                state = END;
            }
            else
            {
                state = INVALID;
            }
            break;

        // Scan for junk at the EOL
        case END:
            if ( !isspace((int)ch) )
            {
                state = INVALID;
            }
            break;

        // Can't get here
        default:
            break;
        }

        if ( state == INVALID )
            return -1;
    }

    if ( snort_pton_address(ipbuf, dest) < 1 )
        return 0;

    if ( *cidrbuf )
    {
        char* end;
        errno = 0;
        int value = strtol(cidrbuf, &end, 10);

        if ( value > dest->get_bits() || value <= 0 || errno == ERANGE )
            return 0;

        if (dest->get_addr()->is_ip4() && value <= 32)
            dest->set_bits(value + 96);
        else
            dest->set_bits(value);
    }

    return 1;
}

int ReputationParser::process_line(char* line, INFO info, const ReputationConfig& config)
{
    SfCidr address;

    if ( !line || *line == '\0' )
        return IP_INSERT_SUCCESS;

    if ( snort_pton(line, &address) < 1 )
        return IP_INVALID;

    return add_ip(&address, info, config);
}

static int update_path_to_file(char* full_filename, unsigned int max_size, const char* filename)
{
    const char* snort_conf_dir = get_snort_conf_dir();

    /*file_name is too long*/
    if ( max_size < strlen(filename) )
    {
        ErrorMessage("The file name length %u is longer than allowed %u.\n",
            (unsigned)strlen(filename), max_size);
        return 0;
    }

    /*
     *  If an absolute path is specified, then use that.
     */
    if (filename[0] == '/')
    {
        snprintf(full_filename, max_size, "%s", filename);
    }
    else
    {
        /*
         * Set up the file name directory.
         */
        if (snort_conf_dir[strlen(snort_conf_dir) - 1] == '/')
        {
            snprintf(full_filename,max_size,
                "%s%s", snort_conf_dir, filename);
        }
        else
        {
            snprintf(full_filename, max_size,
                "%s/%s", snort_conf_dir, filename);
        }
    }
    return 1;
}

static char* get_list_type_name(ListFile* list_info)
{
    if (!list_info)
        return nullptr;
    switch (list_info->list_type)
    {
    case DECISION_NULL:
        return nullptr;
    case BLOCKED:
        return block_info;
    case TRUSTED_DO_NOT_BLOCK:
        return allow_info;
    case MONITORED:
        return monitor_info;
    case TRUSTED:
        return allow_info;
    default:
        return nullptr;
    }
}

void ReputationParser::load_list_file(ListFile* list_info, const ReputationConfig& config,
    ReputationData& data)
{
    char linebuf[MAX_ADDR_LINE_LENGTH];
    char full_path_filename[PATH_MAX+1];
    int addrline = 0;
    FILE* fp = nullptr;
    char* cmt = nullptr;
    char* list_type_name;
    IPrepInfo* ip_info;
    MEM_OFFSET ip_info_ptr;
    uint8_t* base;

    /*entries processing statistics*/
    unsigned int duplicate_count = 0; /*number of duplicates in this file*/
    unsigned int invalid_count = 0;   /*number of invalid entries in this file*/
    unsigned int fail_count = 0;   /*number of invalid entries in this file*/
    unsigned int num_loaded_before = 0;     /*number of valid entries loaded */

    if (data.memcap_reached)
        return;

    update_path_to_file(full_path_filename, PATH_MAX, list_info->file_name.c_str());

    list_type_name = get_list_type_name(list_info);

    if (!list_type_name)
        return;

    /*convert list info to ip entry info*/
    ip_info_ptr = table.segment_snort_calloc(1, sizeof(IPrepInfo));
    if (!(ip_info_ptr))
        return;
    base = (uint8_t*)data.ip_list;
    ip_info = ((IPrepInfo*)&base[ip_info_ptr]);
    ip_info->list_indexes[0] = list_info->list_index;

    if ( SnortConfig::log_verbose() )
    {
    	LogMessage("    Processing %s file %s\n", list_type_name, full_path_filename);
    }

    if ((fp = fopen(full_path_filename, "r")) == nullptr)
    {
        ErrorMessage("Unable to open address file %s, Error: %s\n", full_path_filename,
            get_error(errno));
        return;
    }

    num_loaded_before = table.sfrt_flat_num_entries();
    while ( fgets(linebuf, MAX_ADDR_LINE_LENGTH, fp) )
    {
        int ret;
        addrline++;

        // Remove comments
        if ( (cmt = strchr(linebuf, '#')) )
            *cmt = '\0';

        // Remove newline as well, prevent double newline in logging.
        if ( (cmt = strchr(linebuf, '\n')) )
            *cmt = '\0';

        /* process the line */
        ret = process_line(linebuf, ip_info_ptr, config);

        if (IP_INSERT_SUCCESS == ret)
        {
            continue;
        }
        else if (IP_INSERT_FAILURE == ret && fail_count++ < MAX_MSGS_TO_PRINT)
        {
            ErrorMessage("      (%d) => Failed to insert address: \'%s\'\n", addrline, linebuf);
        }
        else if (IP_INVALID == ret && invalid_count++ < MAX_MSGS_TO_PRINT)
        {
            ErrorMessage("      (%d) => Invalid address: \'%s\'\n", addrline, linebuf);
        }
        else if (IP_INSERT_DUPLICATE == ret && duplicate_count++ < MAX_MSGS_TO_PRINT)
        {
            ErrorMessage("      (%d) => Re-defined address: '%s'\n", addrline, linebuf);
        }
        else if (IP_MEM_ALLOC_FAILURE == ret)
        {
            ErrorMessage(
                "WARNING: %s(%d) => Memcap %u Mbytes reached when inserting IP Address: %s\n",
                full_path_filename, addrline, config.memcap,linebuf);

            data.memcap_reached = true;
            break;
        }
    }

    total_duplicates += duplicate_count;
    total_invalids += invalid_count;
    /*Print out the summary*/
    if (fail_count > MAX_MSGS_TO_PRINT)
        ErrorMessage("    Additional addresses failed insertion but were not listed.\n");
    if (invalid_count > MAX_MSGS_TO_PRINT)
        ErrorMessage("    Additional invalid addresses were not listed.\n");
    if (duplicate_count > MAX_MSGS_TO_PRINT)
        ErrorMessage("    Additional duplicate addresses were not listed.\n");

    if ( SnortConfig::log_verbose() )
    {
        LogMessage("    Reputation entries loaded: %u, invalid: %u, re-defined: %u (from file %s)\n",
            table.sfrt_flat_num_entries() - num_loaded_before,
            invalid_count, duplicate_count, full_path_filename);
    }

    fclose(fp);
}

void ReputationParser::ip_list_init(uint32_t max_entries, const ReputationConfig& config, ReputationData& data)
{
    if ( !data.ip_list )
    {
        uint32_t mem_size;
        mem_size = estimate_size(max_entries, config.memcap);
        data.reputation_segment = (uint8_t*)snort_alloc(mem_size);

        table.segment_meminit(data.reputation_segment, mem_size);

        /*DIR_16x7_4x4 for performance, but memory usage is high
         *Use  DIR_8x16 worst case IPV4 5K, IPV6 15K (bytes)
         *Use  DIR_16x7_4x4 worst case IPV4 500, IPV6 2.5M
         */
        table.sfrt_flat_new(DIR_8x16, IPv6, max_entries, config.memcap);
        data.ip_list = table.get_table();

        if ( !data.ip_list )
        {
            ErrorMessage("Failed to create IP list.\n");
            return;
        }

        total_duplicates = 0;
        for (size_t i = 0; i < data.list_files.size(); i++)
        {
            data.list_files[i]->list_index = (uint8_t)i + 1;
            if (data.list_files[i]->file_type == ALLOW_LIST)
            {
                if (config.allow_action == DO_NOT_BLOCK)
                    data.list_files[i]->list_type = TRUSTED_DO_NOT_BLOCK;
                else
                    data.list_files[i]->list_type = TRUSTED;
            }
            else if (data.list_files[i]->file_type == BLOCK_LIST)
                data.list_files[i]->list_type = BLOCKED;
            else if (data.list_files[i]->file_type == MONITOR_LIST)
                data.list_files[i]->list_type = MONITORED;

            load_list_file(data.list_files[i], config, data);
        }
    }
}

static int num_lines_in_file(char* fname)
{
    FILE* fp;
    int numlines = 0;
    char buf[MAX_ADDR_LINE_LENGTH];

    fp = fopen(fname, "rb");

    if (nullptr == fp)
        return 0;

    while ((fgets(buf, MAX_ADDR_LINE_LENGTH, fp)) != nullptr)
    {
        if (buf[0] != '#')
        {
            numlines++;
            if (numlines == std::numeric_limits<int>::max())
            {
                fclose(fp);
                return std::numeric_limits<int>::max();
            }
        }
    }

    fclose(fp);
    return numlines;
}

static int load_file(int total_lines, const char* path)
{
    int num_lines;
    char full_path_filename[PATH_MAX+1];

    if (!path)
        return 0;

    errno = 0;
    update_path_to_file(full_path_filename,PATH_MAX, path);
    num_lines = num_lines_in_file(full_path_filename);

    if ((0 == num_lines) && (0 != errno))
    {
        ErrorMessage("Unable to open address file %s, Error: %s\n", full_path_filename,
            get_error(errno));
        return 0;
    }

    if (total_lines + num_lines < total_lines)
    {
        ErrorMessage("Too many entries in one file.\n");
        return 0;
    }

    return num_lines;
}

void ReputationParser::estimate_num_entries(ReputationData& data)
{
    data.num_entries = 0;

    for (auto& file : data.list_files)
        data.num_entries += load_file(data.num_entries, file->file_name.c_str());
}

void ReputationParser::add_block_allow_List(const ReputationConfig& config, ReputationData& data)
{
    if (config.blocklist_path.size())
    {
        ListFile* listItem = new ListFile;
        listItem->all_intfs_enabled = true;
        listItem->file_name = config.blocklist_path;
        listItem->file_type = BLOCK_LIST;
        listItem->list_id = 0;
        data.list_files.emplace_back(listItem);
    }
    if (config.allowlist_path.size())
    {
        ListFile* listItem = new ListFile;
        listItem->all_intfs_enabled = true;
        listItem->file_name = config.allowlist_path;
        listItem->file_type = ALLOW_LIST;
        listItem->list_id = 0;
        data.list_files.emplace_back(listItem);
    }
}

/*Ignore the space characters from string*/
static char* ignore_start_space(char* str)
{
    while ((*str) && (isspace((int)*str)))
    {
        str++;
    }
    return str;
}

/*Get file type */
static int get_file_type(char* type_name)
{
    int type = UNKNOWN_LIST;

    if (!type_name)
        return type;

    type_name = ignore_start_space(type_name);

    if (strncasecmp(type_name, TRUST_TYPE_KEYWORD, strlen(TRUST_TYPE_KEYWORD)) == 0)
    {
        type = ALLOW_LIST;
        type_name += strlen(TRUST_TYPE_KEYWORD);
    }
    else if (strncasecmp(type_name, WHITE_TYPE_KEYWORD, strlen(WHITE_TYPE_KEYWORD)) == 0)
    {
        type = ALLOW_LIST;
        type_name += strlen(WHITE_TYPE_KEYWORD);
    }
    else if (strncasecmp(type_name, BLOCK_TYPE_KEYWORD, strlen(BLOCK_TYPE_KEYWORD)) == 0)
    {
        type = BLOCK_LIST;
        type_name += strlen(BLOCK_TYPE_KEYWORD);
    }
    else if (strncasecmp(type_name, MONITOR_TYPE_KEYWORD, strlen(MONITOR_TYPE_KEYWORD)) == 0)
    {
        type = MONITOR_LIST;
        type_name += strlen(MONITOR_TYPE_KEYWORD);
    }

    if ( type != UNKNOWN_LIST )
    {
        /*Ignore spaces in the end*/
        type_name = ignore_start_space(type_name);

        if ( *type_name )
        {
            type = UNKNOWN_LIST;
        }
    }
    return type;
}

//The format of manifest is:
//    file_name, list_id, action (block, allow, monitor), interface information
//If no interface information provided, this means all interfaces are applied.

static bool process_line_in_manifest(ListFile* list_item, const char* manifest, const char* line,
    int line_number, const ReputationConfig& config, ReputationData& data)
{
    char* token;
    int token_index = 0;
    char* next_ptr = const_cast<char*>(line);
    bool has_intf = false;

    list_item->intfs.clear();

    while ((token = strtok_r(next_ptr, MANIFEST_SEPARATORS, &next_ptr)) != nullptr)
    {
        char* end_str;
        long intf_id;
        long list_id;

        switch (token_index)
        {
        case 0:    // File name
            list_item->file_name = config.list_dir + '/' + token;
            break;

        case 1:    // List ID
            list_id = SnortStrtol(token, &end_str, 10);
            end_str = ignore_start_space(end_str);
            if ( *end_str )
            {
                ErrorMessage("%s(%d) => Bad value (%s) specified for listID. "
                    "Please specify an integer between 0 and %u.\n",
                    manifest, line_number, token, MAX_LIST_ID);
                return false;
            }

            if ((list_id < 0)  || (list_id > MAX_LIST_ID) || (errno == ERANGE))
            {
                ErrorMessage(" %s(%d) => Value specified (%s) is out of "
                    "bounds.  Please specify an integer between 0 and %u.\n",
                    manifest, line_number, token, MAX_LIST_ID);
                return false;
            }
            list_item->list_id = (uint32_t)list_id;
            break;

        case 2:    // Action
            token = ignore_start_space(token);
            list_item->file_type = get_file_type(token);
            if (UNKNOWN_LIST == list_item->file_type)
            {
                ErrorMessage(" %s(%d) => Unknown action specified (%s)."
                    " Please specify a value: %s | %s | %s | %s.\n", manifest, line_number, token,
                    WHITE_TYPE_KEYWORD, TRUST_TYPE_KEYWORD, BLOCK_TYPE_KEYWORD, MONITOR_TYPE_KEYWORD);
                return false;
            }
            break;

        default:
            token= ignore_start_space(token);
            if ('0' == (*token))
                break;
            intf_id = SnortStrtol(token, &end_str, 10);
            end_str = ignore_start_space(end_str);

            if ( *end_str )
            {
                ErrorMessage("%s(%d) => Bad value (%s) specified for interface. "
                    "Please specify an integer between 0 and %u.\n",
                    manifest, line_number, token, MAX_NUM_INTFS);
                return false;
            }
            if ((intf_id < 0)  || (intf_id > MAX_NUM_INTFS ) || (errno == ERANGE))
            {
                ErrorMessage(" %s(%d) => Value specified (%s) for interface is "
                    "out of bounds. Please specify an integer between 0 and %u.\n",
                    manifest, line_number, token, MAX_NUM_INTFS);
                return false;
            }

            list_item->intfs.emplace(intf_id);
            has_intf = true;
        }

        token_index++;
    }

    if ( token_index < MIN_MANIFEST_COLUMNS )
    {
        if ( token_index > 0 )
        {
            ErrorMessage("%s(%d) => Too few columns in line: %s.\n", manifest, line_number, line);
        }
        return false;
    }

    if (!has_intf)
    {
        list_item->all_intfs_enabled = true;
    }

    data.list_files.emplace_back(list_item);
    return true;
}

void ReputationParser::read_manifest(const char* manifest_file, const ReputationConfig& config, ReputationData& data)
{
    char full_path_dir[PATH_MAX+1];
    update_path_to_file(full_path_dir, PATH_MAX, config.list_dir.c_str());
    std::string manifest_full_path = std::string(full_path_dir) + '/' + manifest_file;

    std::fstream fs;
    fs.open (manifest_full_path, std::fstream::in);

    if (!fs.good())
    {
        ErrorMessage("Can't open file: %s\n", manifest_full_path.c_str());
        return;
    }

    int line_number = 0;
    std::string line;
    while (std::getline(fs, line))
    {
        line_number++;

        /* remove comments */
        size_t pos = line.find_first_of('#');
        if (pos != line.npos)
           line[pos] = '\0';

        //Processing the line
        ListFile* list_item = new ListFile;
        if (!process_line_in_manifest(
                list_item, manifest_file, line.c_str(), line_number, config, data))
            delete list_item;
    }

    fs.close();
}

