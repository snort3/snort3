//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#define PCAP_MAGIC_NUMBER 0xa1b2c3d4
#define PCAP_TIMEZONE 0
#define PCAP_SIGFIGS 0
#define PCAP_SNAPLEN 65535
#define ETHERNET 1
#define PCAP_LINKTYPE ETHERNET
#define MAX_U2RECORD_DATA_LENGTH 65536

static int GetRecord(FILE* input, u2record* rec);
static int PcapInitOutput(FILE* output);
static int PcapConversion(u2record* rec, FILE* output);

static int ConvertLog(FILE* input, FILE* output, const char* format)
{
    u2record tmp_record;

    /* Determine conversion function */
    int (* ConvertRecord)(u2record*, FILE*) = nullptr;

    /* This will become an if/else series once more formats are supported.
     * Callbacks are used so that this comparison only needs to happen once. */
    if (strncasecmp(format, "pcap", 4) == 0)
    {
        ConvertRecord = PcapConversion;
    }

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
    while ( !(feof(input) || ferror(input) || ferror(output)) )
    {
        if (GetRecord(input, &tmp_record) == FAILURE)
        {
            break;
        }
        if (ConvertRecord(&tmp_record, output) == FAILURE)
        {
            break;
        }
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
    if (ferror(output))
    {
        fprintf(stderr, "Error reading output file, aborting...\n");
        return FAILURE;
    }

    return SUCCESS;
}

/* Create and write the pcap file's global header */
static int PcapInitOutput(FILE* output)
{
    size_t ret;
    struct pcap_file_header hdr;

    hdr.magic = PCAP_MAGIC_NUMBER;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = PCAP_TIMEZONE;
    hdr.sigfigs = PCAP_SIGFIGS;
    hdr.snaplen = PCAP_SNAPLEN;
    hdr.linktype = PCAP_LINKTYPE;

    ret = fwrite( (void*)&hdr, sizeof(struct pcap_file_header), 1, output);
    if (ret < 1)
    {
        fprintf(stderr, "Error: Unable to write pcap file header\n");
        return FAILURE;
    }
    return SUCCESS;
}

/* Convert a unified2 packet record to pcap format, then dump */
static int PcapConversion(u2record* rec, FILE* output)
{
    Serial_Unified2Packet packet;
    struct pcap_pkthdr pcap_hdr;
    uint32_t* field;
    uint8_t* pcap_data;
    static int packet_found = 0;

    /* Ignore IDS Events. We are only interested in Packets. */
    if (rec->type != UNIFIED2_PACKET)
    {
        return SUCCESS;
    }

    /* Initialize the pcap file if this is the first packet */
    if (!packet_found)
    {
        if (PcapInitOutput(output) == FAILURE)
        {
            return FAILURE;
        }
        packet_found = 1;
    }

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
    pcap_dump( (uint8_t*)output, &pcap_hdr, (uint8_t*)pcap_data);

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
    FILE* output_file = nullptr;

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

    /* Open the files */
    if ((input_file = fopen(input_filename, "r")) == nullptr)
    {
        fprintf(stderr, "Unable to open file: %s\n", input_filename);
        return FAILURE;
    }
    if ((output_file = fopen(output_filename, "w")) == nullptr)
    {
        fclose(input_file);
        fprintf(stderr, "Unable to open/create file: %s\n", output_filename);
        return FAILURE;
    }

    ConvertLog(input_file, output_file, output_type);

    if (fclose(input_file) != 0)
    {
        errnum = errno;
        fprintf(stderr, "Error closing input: %s\n", strerror(errnum));
    }
    if (fclose(output_file) != 0)
    {
        errnum = errno;
        fprintf(stderr, "Error closing output: %s\n", strerror(errnum));
    }

    return 0;
}

