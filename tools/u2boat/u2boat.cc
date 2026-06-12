//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// u2boat.cc author Ryan Jordan <ryan.jordan@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "../u2spewfoo/u2_common.h"

#define FAILURE (-1)
#define SUCCESS 0

#define PCAP_SNAPLEN 65535
#define ETHERNET 1
#define PCAP_LINKTYPE ETHERNET
#define MAX_U2RECORD_DATA_LENGTH 65536

static int GetRecord(FILE* input, u2record* rec);
static int PcapConversion(u2record* rec, pcap_dumper_t* dumper);

static int ConvertLog(FILE* input, pcap_dumper_t* dumper, const char* format)
{
    u2record tmp_record;

    /* Determine conversion function */
    int (* ConvertRecord)(u2record*, pcap_dumper_t*) = nullptr;

    /* This will become an if/else series once more formats are supported.
     * Callbacks are used so that this comparison only needs to happen once. */
    if (strncasecmp(format, "pcap", 4) == 0)
        ConvertRecord = PcapConversion;

    if (ConvertRecord == nullptr)
    {
        fprintf(stderr, "Error setting conversion routine, aborting...\n");
        return FAILURE;
    }

    /* Initialize the record's data pointer */
    tmp_record.data = (uint8_t*)malloc(MAX_U2RECORD_DATA_LENGTH * sizeof(uint8_t));
    if (tmp_record.data == nullptr)
    {
        fprintf(stderr, "Error allocating memory, aborting...\n");
        return FAILURE;
    }

    /* Run through input file and convert records */
    FILE* dump_file = pcap_dump_file(dumper);
    while ( !(feof(input) || ferror(input) || ferror(dump_file)) )
    {
        if (GetRecord(input, &tmp_record) == FAILURE)
            break;
        if (ConvertRecord(&tmp_record, dumper) == FAILURE)
            break;
    }
    if (tmp_record.data != nullptr)
    {
        free(tmp_record.data);
        tmp_record.data = nullptr;
    }
    if (ferror(input))
    {
        fprintf(stderr, "Error reading input file, aborting...\n");
        return FAILURE;
    }
    if (ferror(dump_file))
    {
        fprintf(stderr, "Error writing output file, aborting...\n");
        return FAILURE;
    }

    return SUCCESS;
}

/* Convert a unified2 packet record to pcap format, then dump */
static int PcapConversion(u2record* rec, pcap_dumper_t* dumper)
{
    Serial_Unified2Packet packet;
    struct pcap_pkthdr pcap_hdr;
    uint32_t* field;
    uint8_t* pcap_data;

    /* Ignore IDS Events. We are only interested in Packets. */
    if (rec->type != UNIFIED2_PACKET)
        return SUCCESS;

    /* Fill out the Serial_Unified2Packet */
    memcpy(&packet, rec->data, sizeof(Serial_Unified2Packet));

    /* Unified 2 records are always stored in network order.
     * Convert all fields except packet data to host order */
    field = (uint32_t*)&packet;
    while (field < (uint32_t*)packet.packet_data)
    {
        *field = ntohl(*field);
        field++;
    }

    /* Create a pcap packet header */
    pcap_hdr.ts.tv_sec = packet.packet_second;
    pcap_hdr.ts.tv_usec = packet.packet_microsecond;
    pcap_hdr.caplen = packet.packet_length;
    pcap_hdr.len = packet.packet_length;

    /* Write to the pcap file */
    pcap_data = rec->data + sizeof(Serial_Unified2Packet) - 4;
    pcap_dump((u_char*)dumper, &pcap_hdr, pcap_data);

    return SUCCESS;
}

/* Retrieve a single unified2 record from input file */
static int GetRecord(FILE* input, u2record* rec)
{
    uint32_t items_read;
    static uint32_t buffer_size = MAX_U2RECORD_DATA_LENGTH;
    uint8_t* tmp;

    if (!input || !rec)
        return FAILURE;

    items_read = fread(rec, sizeof(uint32_t), 2, input);
    if (items_read != 2)
    {
        if ( !feof(input) ) /* Not really an error if at EOF */
        {
            fprintf(stderr, "Error: incomplete record.\n");
        }
        return FAILURE;
    }
    /* Type and Length are stored in network order */
    rec->type = ntohl(rec->type);
    rec->length = ntohl(rec->length);

    /* Read in the data portion of the record */
    if (rec->length > buffer_size)
    {
        // If we fail to allocate here, we simply error out
        // coverity[tainted_scalar]
        tmp = (uint8_t*)malloc(rec->length * sizeof(uint8_t));
        if (tmp == nullptr)
        {
            fprintf(stderr, "Error: memory allocation failed.\n");
            return FAILURE;
        }
        else
        {
            if (rec->data != nullptr)
            {
                free(rec->data);
            }
            rec->data = tmp;
            buffer_size = rec->length;
        }
    }
    // coverity[tainted_scalar]
    items_read = fread(rec->data, sizeof(uint8_t), rec->length, input);
    if (items_read != rec->length)
    {
        fprintf(stderr, "Error: incomplete record. %u of %u bytes read.\n",
            items_read, rec->length);
        return FAILURE;
    }

    return SUCCESS;
}

int main(int argc, char* argv[])
{
    char* input_filename = nullptr;
    char* output_filename = nullptr;
    const char* output_type = nullptr;

    FILE* input_file = nullptr;
    pcap_t* pcap = nullptr;
    pcap_dumper_t* dumper = nullptr;

    int c, errnum;
    opterr = 0;

    /* Use Getopt to parse options */
    while ((c = getopt (argc, argv, "t:")) != -1)
    {
        switch (c)
        {
        case 't':
            output_type = optarg;
            break;
        case '?':
            if (optopt == 't')
                fprintf(stderr,
                    "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf(stderr, "Unknown option -%c.\n", optopt);
            return FAILURE;
        default:
            abort();
        }
    }

    /* At this point, there should be two filenames remaining. */
    if (optind != (argc - 2))
    {
        fprintf(stderr, "Usage: u2boat [-t type] <infile> <outfile>\n");
        return FAILURE;
    }

    input_filename = argv[optind];
    output_filename = argv[optind+1];

    /* Check inputs */
    if (input_filename == nullptr)
    {
        fprintf(stderr, "Error: Input filename must be specified.\n");
        return FAILURE;
    }
    if (output_type == nullptr)
    {
        fprintf(stdout, "Defaulting to pcap output.\n");
        output_type = "pcap";
    }
    if (strcasecmp(output_type, "pcap"))
    {
        fprintf(stderr, "Invalid output type. Valid types are: pcap\n");
        return FAILURE;
    }
    if (output_filename == nullptr)
    {
        fprintf(stderr, "Error: Output filename must be specified.\n");
        return FAILURE;
    }

    /* Open the input file */
    if ((input_file = fopen(input_filename, "r")) == nullptr)
    {
        fprintf(stderr, "Unable to open file: %s\n", input_filename);
        return FAILURE;
    }

    /* Open the pcap output file */
    pcap = pcap_open_dead(PCAP_LINKTYPE, PCAP_SNAPLEN);
    if (pcap == nullptr)
    {
        fclose(input_file);
        fprintf(stderr, "Unable to create pcap handle\n");
        return FAILURE;
    }
    dumper = pcap_dump_open(pcap, output_filename);
    if (dumper == nullptr)
    {
        fclose(input_file);
        pcap_close(pcap);
        fprintf(stderr, "Unable to open/create file: %s\n", output_filename);
        return FAILURE;
    }

    ConvertLog(input_file, dumper, output_type);

    if (fclose(input_file) != 0)
    {
        errnum = errno;
        fprintf(stderr, "Error closing input: %s\n", strerror(errnum));
    }
    pcap_dump_close(dumper);
    pcap_close(pcap);

    return 0;
}

