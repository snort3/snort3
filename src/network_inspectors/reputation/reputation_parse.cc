//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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

#include <limits.h>
#include <netinet/in.h>

#include <cassert>
#include <limits>

#include "log/messages.h"
#include "parser/config_file.h"
#include "sfip/sf_cidr.h"
#include "utils/util.h"

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

static char black_info[] = "blacklist";
static char white_info[] = "whitelist";
static char monitor_info[] = "monitorlist";

#define MAX_MSGS_TO_PRINT      20

unsigned long total_duplicates;
unsigned long total_invalids;

int totalNumEntries = 0;

ReputationConfig::~ReputationConfig()
{
    if (reputation_segment != nullptr)
        snort_free(reputation_segment);

    if (blacklist_path)
        snort_free(blacklist_path);

    if (whitelist_path)
        snort_free(whitelist_path);
}


static uint32_t estimateSizeFromEntries(uint32_t num_entries, uint32_t memcap)
{
    uint64_t size;
    uint64_t sizeFromEntries;

    /*memcap value is in Megabytes*/
    size = (uint64_t)memcap << 20;

    if (size > std::numeric_limits<uint32_t>::max())
        size = std::numeric_limits<uint32_t>::max();

    /*Worst case,  15k ~ 2^14 per entry, plus one Megabytes for empty table*/
    if (num_entries > ((std::numeric_limits<uint32_t>::max() - (1 << 20))>> 15))
        sizeFromEntries = std::numeric_limits<uint32_t>::max();
    else
        sizeFromEntries = (num_entries << 15) + (1 << 20);

    if (size > sizeFromEntries)
    {
        size = sizeFromEntries;
    }

    return (uint32_t)size;
}

void IpListInit(uint32_t maxEntries, ReputationConfig* config)
{
    uint8_t* base;
    ListInfo* whiteInfo;
    ListInfo* blackInfo;
    MEM_OFFSET list_ptr;

    if ( !config->iplist )
    {
        uint32_t mem_size;
        mem_size = estimateSizeFromEntries(maxEntries, config->memcap);
        config->reputation_segment = (uint8_t*)snort_alloc(mem_size);

        segment_meminit(config->reputation_segment, mem_size);
        base = config->reputation_segment;

        /*DIR_16x7_4x4 for performance, but memory usage is high
         *Use  DIR_8x16 worst case IPV4 5K, IPV6 15K (bytes)
         *Use  DIR_16x7_4x4 worst case IPV4 500, IPV6 2.5M
         */
        config->iplist = sfrt_flat_new(DIR_8x16, IPv6, maxEntries, config->memcap);

        if ( !config->iplist )
            FatalError("Failed to create IP list.\n");

        list_ptr = segment_snort_calloc((size_t)DECISION_MAX, sizeof(ListInfo));

        if ( !list_ptr )
            FatalError("Failed to create IP list.\n");

        config->iplist->list_info = list_ptr;

        config->local_black_ptr = list_ptr + BLACKLISTED * sizeof(ListInfo);
        blackInfo = (ListInfo*)&base[config->local_black_ptr];
        blackInfo->listType = BLACKLISTED;
        blackInfo->listIndex = BLACKLISTED + 1;
        if (UNBLACK == config->whiteAction)
        {
            config->local_white_ptr = list_ptr + WHITELISTED_UNBLACK * sizeof(ListInfo);
            whiteInfo = (ListInfo*)&base[config->local_white_ptr];
            whiteInfo->listType = WHITELISTED_UNBLACK;
            whiteInfo->listIndex = WHITELISTED_UNBLACK + 1;
        }
        else
        {
            config->local_white_ptr = list_ptr + WHITELISTED_TRUST * sizeof(ListInfo);
            whiteInfo = (ListInfo*)&base[config->local_white_ptr];
            whiteInfo->listType = WHITELISTED_TRUST;
            whiteInfo->listIndex = WHITELISTED_TRUST + 1;
        }
    }
}

static inline IPrepInfo* getLastIndex(IPrepInfo* repInfo, uint8_t* base, int* lastIndex)
{
    int i;

    assert(repInfo);

    /* Move to the end of current info*/
    while (repInfo->next)
    {
        repInfo =  (IPrepInfo*)&base[repInfo->next];
    }

    for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
    {
        if (!repInfo->listIndexes[i])
            break;
    }

    if (i > 0)
    {
        *lastIndex = i-1;
        return repInfo;
    }
    else
    {
        return nullptr;
    }
}

static inline int duplicateInfo(IPrepInfo* destInfo,IPrepInfo* currentInfo,
    uint8_t* base)
{
    int bytesAllocated = 0;

    while (currentInfo)
    {
        INFO nextInfo;
        *destInfo = *currentInfo;
        if (!currentInfo->next)
            break;
        nextInfo = segment_snort_calloc(1,sizeof(IPrepInfo));
        if (!nextInfo)
        {
            destInfo->next = 0;
            return -1;
        }
        else
        {
            destInfo->next = nextInfo;
        }
        bytesAllocated += sizeof(IPrepInfo);
        currentInfo =  (IPrepInfo*)&base[currentInfo->next];
        destInfo =  (IPrepInfo*)&base[nextInfo];
    }

    return bytesAllocated;
}

static int64_t updateEntryInfo(INFO* current, INFO new_entry, SaveDest saveDest, uint8_t* base)
{
    IPrepInfo* currentInfo;
    IPrepInfo* newInfo;
    IPrepInfo* destInfo;
    IPrepInfo* lastInfo;
    int64_t bytesAllocated = 0;
    int i;
    char newIndex;

    if (!(*current))
    {
        /* Copy the data to segment memory*/
        *current = segment_snort_calloc(1,sizeof(IPrepInfo));
        if (!(*current))
        {
            return -1;
        }
        bytesAllocated = sizeof(IPrepInfo);
    }

    if (*current == new_entry)
        return bytesAllocated;

    currentInfo = (IPrepInfo*)&base[*current];
    newInfo = (IPrepInfo*)&base[new_entry];

    /*The latest information is always the last entry
     */
    lastInfo = getLastIndex(newInfo, base, &i);

    if (!lastInfo)
    {
        return bytesAllocated;
    }
    newIndex = lastInfo->listIndexes[i++];

    DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Current IP reputation information: \n"); );
    DEBUG_WRAP(ReputationPrintRepInfo(currentInfo, base); );
    DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "New IP reputation information: \n"); );
    DEBUG_WRAP(ReputationPrintRepInfo(newInfo, base); );

    if (SAVE_TO_NEW == saveDest)
    {
        int bytesDuplicated;

        /* When updating new entry, current information should be reserved
         * because current information is inherited from parent
         */
        if ((bytesDuplicated = duplicateInfo(newInfo, currentInfo, base)) < 0)
            return -1;
        else
            bytesAllocated += bytesDuplicated;

        destInfo = newInfo;
    }
    else
    {
        destInfo = currentInfo;
    }

    /* Add the new list information to the end
     * This way, the order of list information is preserved.
     * The first one always has the highest priority,
     * because it is checked first during lookup.
     */

    while (destInfo->next)
    {
        destInfo =  (IPrepInfo*)&base[destInfo->next];
    }

    for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
    {
        if (!destInfo->listIndexes[i])
            break;
        else if (destInfo->listIndexes[i] == newIndex)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Final IP reputation information: \n"); );
            DEBUG_WRAP(ReputationPrintRepInfo(destInfo, base); );
            return bytesAllocated;
        }
    }

    if (i < NUM_INDEX_PER_ENTRY)
    {
        destInfo->listIndexes[i] = newIndex;
    }
    else
    {
        IPrepInfo* nextInfo;
        MEM_OFFSET ipInfo_ptr = segment_snort_calloc(1,sizeof(IPrepInfo));
        if (!ipInfo_ptr)
            return -1;
        destInfo->next = ipInfo_ptr;
        nextInfo = (IPrepInfo*)&base[destInfo->next];
        nextInfo->listIndexes[0] = newIndex;
        bytesAllocated += sizeof(IPrepInfo);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Final IP reputation information: \n"); );
    DEBUG_WRAP(ReputationPrintRepInfo(destInfo, base); );

    return bytesAllocated;
}

static int AddIPtoList(SfCidr* ipAddr,INFO ipInfo_ptr, ReputationConfig* config)
{
    int iRet;
    int iFinalRet = IP_INSERT_SUCCESS;
    /*This variable is used to check whether a more generic address
     * overrides specific address
     */
    uint32_t usageBeforeAdd;
    uint32_t usageAfterAdd;

#ifdef DEBUG_MSGS
    if (nullptr != sfrt_flat_lookup(ipAddr->get_addr(), config->iplist))
    {
        DebugFormat(DEBUG_REPUTATION, "Find address before insert: %s\n", ipAddr->ntoa() );
    }
    else
    {
        DebugFormat(DEBUG_REPUTATION,
            "Can't find address before insert: %s\n", ipAddr->ntoa() );
    }
#endif

    usageBeforeAdd =  sfrt_flat_usage(config->iplist);

    /*Check whether the same or more generic address is already in the table*/
    if (nullptr != sfrt_flat_lookup(ipAddr->get_addr(), config->iplist))
    {
        iFinalRet = IP_INSERT_DUPLICATE;
    }

    iRet = sfrt_flat_insert(ipAddr, (unsigned char)ipAddr->get_bits(), ipInfo_ptr, RT_FAVOR_ALL,
        config->iplist, &updateEntryInfo);
    DEBUG_WRAP(DebugFormat(DEBUG_REPUTATION, "Unused memory: %zu \n",segment_unusedmem()); );

    if (RT_SUCCESS == iRet)
    {
#ifdef DEBUG_MSGS
        IPrepInfo* result;
        DebugFormat(DEBUG_REPUTATION, "Number of entries input: %d, in table: %u \n",
            totalNumEntries,sfrt_flat_num_entries(config->iplist) );
        DebugFormat(DEBUG_REPUTATION, "Memory allocated: %u \n",sfrt_flat_usage(config->iplist) );
        result = (IPrepInfo*)sfrt_flat_lookup(ipAddr->get_addr(), config->iplist);
        if (nullptr != result)
        {
            DebugFormat(DEBUG_REPUTATION, "Find address after insert: %s \n", ipAddr->ntoa() );
            DEBUG_WRAP(ReputationPrintRepInfo(result, (uint8_t*)config->iplist); );
        }
#endif
        totalNumEntries++;
    }
    else if (MEM_ALLOC_FAILURE == iRet)
    {
        iFinalRet = IP_MEM_ALLOC_FAILURE;
        DEBUG_WRAP(DebugFormat(DEBUG_REPUTATION, "Insert error: %d for address: %s \n",iRet,
            ipAddr->ntoa() ); );
    }
    else
    {
        iFinalRet = IP_INSERT_FAILURE;
        DEBUG_WRAP(DebugFormat(DEBUG_REPUTATION, "Insert error: %d for address: %s \n",iRet,
            ipAddr->ntoa() ); );
    }

    usageAfterAdd = sfrt_flat_usage(config->iplist);
    /*Compare in the same scale*/
    if (usageAfterAdd  > (config->memcap << 20))
    {
        iFinalRet = IP_MEM_ALLOC_FAILURE;
    }
    /*Check whether there a more specific address will be overridden*/
    if (usageBeforeAdd > usageAfterAdd )
    {
        iFinalRet = IP_INSERT_DUPLICATE;
    }

    return iFinalRet;
}

// FIXIT-L X Remove this or at least move it to SfCidr?
static int snort_pton__address(char const* src, SfCidr* dest)
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

    if ( snort_pton__address(ipbuf, dest) < 1 )
        return 0;

    if ( *cidrbuf )
    {
        char* end;
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

static int ProcessLine(char* line, INFO info, ReputationConfig* config)
{
    SfCidr address;

    if ( !line || *line == '\0' )
        return IP_INSERT_SUCCESS;

    if ( snort_pton(line, &address) < 1 )
        return IP_INVALID;

    return AddIPtoList(&address, info, config);
}

static int UpdatePathToFile(char* full_path_filename, unsigned int max_size, char* filename)
{
    const char* snort_conf_dir = get_snort_conf_dir();

    if (!snort_conf_dir || !(*snort_conf_dir) || !full_path_filename || !filename)
        FatalError("can't create path.\n");

    /*filename is too long*/
    if ( max_size < strlen(filename) )
    {
        FatalError("The file name length %u is longer than allowed %u.\n",
            (unsigned)strlen(filename), max_size);
    }

    /*
     *  If an absolute path is specified, then use that.
     */
#ifndef WIN32
    if (filename[0] == '/')
    {
        snprintf(full_path_filename, max_size, "%s", filename);
    }
    else
    {
        /*
         * Set up the file name directory.
         */
        if (snort_conf_dir[strlen(snort_conf_dir) - 1] == '/')
        {
            snprintf(full_path_filename,max_size,
                "%s%s", snort_conf_dir, filename);
        }
        else
        {
            snprintf(full_path_filename, max_size,
                "%s/%s", snort_conf_dir, filename);
        }
    }
#else
    if (strlen(filename)>3 && filename[1]==':' && filename[2]=='\\')
    {
        snprintf(full_path_filename, max_size, "%s", filename);
    }
    else
    {
        /*
         **  Set up the file name directory
         */
        if (snort_conf_dir[strlen(snort_conf_dir) - 1] == '\\' ||
            snort_conf_dir[strlen(snort_conf_dir) - 1] == '/' )
        {
            snprintf(full_path_filename,max_size,
                "%s%s", snort_conf_dir, filename);
        }
        else
        {
            snprintf(full_path_filename, max_size,
                "%s\\%s", snort_conf_dir, filename);
        }
    }
#endif
    return 1;
}

static char* GetListInfo(INFO info)
{
    uint8_t* base;
    ListInfo* info_value;
    base = (uint8_t*)segment_basePtr();
    info_value = (ListInfo*)(&base[info]);
    if (!info_value)
        return nullptr;
    switch (info_value->listType)
    {
    case DECISION_NULL:
        return nullptr;
    case BLACKLISTED:
        return black_info;
    case WHITELISTED_UNBLACK:
        return white_info;
    case MONITORED:
        return monitor_info;
    case WHITELISTED_TRUST:
        return white_info;
    default:
        break;
    }
    return nullptr;
}

void LoadListFile(char* filename, INFO info, ReputationConfig* config)
{
    char linebuf[MAX_ADDR_LINE_LENGTH];
    char full_path_filename[PATH_MAX+1];
    int addrline = 0;
    FILE* fp = nullptr;
    char* cmt = nullptr;
    char* list_info;
    ListInfo* listInfo;
    IPrepInfo* ipInfo;
    MEM_OFFSET ipInfo_ptr;
    uint8_t* base;

    /*entries processing statistics*/
    unsigned int duplicate_count = 0; /*number of duplicates in this file*/
    unsigned int invalid_count = 0;   /*number of invalid entries in this file*/
    unsigned int fail_count = 0;   /*number of invalid entries in this file*/
    unsigned int num_loaded_before = 0;     /*number of valid entries loaded */

    if ((nullptr == filename)||(0 == info)|| (nullptr == config)||config->memCapReached)
        return;

    UpdatePathToFile(full_path_filename, PATH_MAX, filename);

    list_info = GetListInfo(info);

    if (!list_info)
        return;

    /*convert list info to ip entry info*/
    ipInfo_ptr = segment_snort_calloc(1,sizeof(IPrepInfo));
    if (!(ipInfo_ptr))
    {
        return;
    }
    base = (uint8_t*)config->iplist;
    ipInfo = ((IPrepInfo*)&base[ipInfo_ptr]);
    listInfo = ((ListInfo*)&base[info]);
    ipInfo->listIndexes[0] = listInfo->listIndex;

    LogMessage("    Processing %s file %s\n", list_info, full_path_filename);

    if ((fp = fopen(full_path_filename, "r")) == nullptr)
    {
        ErrorMessage("Unable to open address file %s, Error: %s\n", full_path_filename, get_error(errno));
        return;
    }

    num_loaded_before = sfrt_flat_num_entries(config->iplist);
    while ( fgets(linebuf, MAX_ADDR_LINE_LENGTH, fp) )
    {
        int iRet;
        addrline++;

        DEBUG_WRAP(DebugFormat(DEBUG_REPUTATION, "Reputation configurations: %s\n",linebuf); );

        // Remove comments
        if ( (cmt = strchr(linebuf, '#')) )
            *cmt = '\0';

        // Remove newline as well, prevent double newline in logging.
        if ( (cmt = strchr(linebuf, '\n')) )
            *cmt = '\0';

        DEBUG_WRAP(DebugFormat(DEBUG_REPUTATION, "Reputation configurations: %s\n",linebuf); );

        /* process the line */
        iRet = ProcessLine(linebuf, ipInfo_ptr, config);

        if (IP_INSERT_SUCCESS == iRet)
        {
            continue;
        }
        else if (IP_INSERT_FAILURE == iRet && fail_count++ < MAX_MSGS_TO_PRINT)
        {
            ErrorMessage("      (%d) => Failed to insert address: \'%s\'\n", addrline, linebuf);
        }
        else if (IP_INVALID == iRet && invalid_count++ < MAX_MSGS_TO_PRINT)
        {
            ErrorMessage("      (%d) => Invalid address: \'%s\'\n", addrline, linebuf);
        }
        else if (IP_INSERT_DUPLICATE == iRet && duplicate_count++ < MAX_MSGS_TO_PRINT)
        {
            ErrorMessage("      (%d) => Re-defined address: '%s'\n", addrline, linebuf);
        }
        else if (IP_MEM_ALLOC_FAILURE == iRet)
        {
            ErrorMessage(
                "WARNING: %s(%d) => Memcap %u Mbytes reached when inserting IP Address: %s\n",
                full_path_filename, addrline, config->memcap,linebuf);

            config->memCapReached = true;
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

    LogMessage("    Reputation entries loaded: %u, invalid: %u, re-defined: %u (from file %s)\n",
        sfrt_flat_num_entries(config->iplist) - num_loaded_before,
        invalid_count, duplicate_count, full_path_filename);

    fclose(fp);
}

static int numLinesInFile(char* fname)
{
    FILE* fp;
    uint32_t numlines = 0;
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

static int LoadFile(int totalLines, char* path)
{
    int numlines;
    char full_path_filename[PATH_MAX+1];

    if (!path)
        return 0;

    errno = 0;
    UpdatePathToFile(full_path_filename,PATH_MAX, path);
    numlines = numLinesInFile(full_path_filename);

    if ((0 == numlines) && (0 != errno))
    {
        FatalError("Unable to open address file %s, Error: %s\n", full_path_filename, get_error(errno));
    }

    if (totalLines + numlines < totalLines)
    {
        FatalError("Too many entries in one file.\n");
    }

    return numlines;
}

void EstimateNumEntries(ReputationConfig* config)
{
    int totalLines = 0;

    totalLines += LoadFile(totalLines, config->blacklist_path);
    totalLines += LoadFile(totalLines, config->whitelist_path);

    config->numEntries = totalLines;
}

#ifdef DEBUG_MSGS
static void ReputationRepInfo(IPrepInfo* repInfo, uint8_t* base, char* repInfoBuff,
    int bufLen)
{
    char* index = repInfoBuff;
    int len = bufLen -1;
    int writed;

    writed = snprintf(index, len, "Reputation Info: ");
    if (writed >= len || writed < 0)
        return;

    index += writed;
    len -= writed;

    while (repInfo)
    {
        int i;
        for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
        {
            writed = snprintf(index, len, "%d,",repInfo->listIndexes[i]);
            if (writed >= len || writed < 0)
                return;
            else
            {
                index += writed;
                len -=writed;
            }
        }
        writed = snprintf(index, len, "->");
        if (writed >= len || writed < 0)
            return;
        else
        {
            index += writed;
            len -=writed;
        }

        if (!repInfo->next)
            break;

        repInfo = (IPrepInfo*)(&base[repInfo->next]);
    }
}

void ReputationPrintRepInfo(IPrepInfo* repInfo, uint8_t* base)
{
    char repInfoBuff[STD_BUF];
    int len = STD_BUF -1;

    repInfoBuff[STD_BUF -1] = '\0';

    ReputationRepInfo(repInfo, base, repInfoBuff, len);

    DEBUG_WRAP(DebugFormat(DEBUG_REPUTATION, "Reputation Info: %s \n",
        repInfoBuff); );
}

#endif

