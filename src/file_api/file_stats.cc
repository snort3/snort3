//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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
/*
 **
 **  Author(s):  Hui Cao <huica@cisco.com>
 **
 **  NOTES
 **  5.25.13 - Initial Source Code. Hui Cao
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>

#include "file_stats.h"
#include "file_capture.h"
#include "file_config.h"

#include "main/snort_types.h"
#include "main/snort_config.h"
#include "utils/stats.h"
#include "log/messages.h"

FileStats file_stats;

void print_file_stats()
{
    int i;
    uint64_t processed_total[2];
    uint64_t processed_data_total[2];

    if (!file_stats.files_total)
        return;

    uint64_t check_total = 0;

    for (i = 0; i < FILE_ID_MAX; i++)
    {
        check_total += file_stats.files_processed[i][0];
        check_total += file_stats.files_processed[i][1];
    }

    if ( !check_total )
        return;

    LogLabel("file type stats (files)");

    LogMessage("         Type              Download   Upload \n");

    processed_total[0] = 0;
    processed_total[1] = 0;
    processed_data_total[0] = 0;
    processed_data_total[1] = 0;

    for (i = 0; i < FILE_ID_MAX; i++)
    {
        const char* type_name = file_type_name(i).c_str();
        if (type_name &&
            (file_stats.files_processed[i][0] || file_stats.files_processed[i][1] ))
        {
            LogMessage("%12s(%3d)          " FMTu64("-10") " " FMTu64("-10") " \n",
                type_name, i,
                file_stats.files_processed[i][0],
                file_stats.files_processed[i][1]);
            processed_total[0]+= file_stats.files_processed[i][0];
            processed_total[1]+= file_stats.files_processed[i][1];
        }
    }

    LogMessage("            Total          " FMTu64("-10") " " FMTu64("-10") " \n",
        processed_total[0], processed_total[1]);

    LogLabel("file type stats (bytes)");

    LogMessage("         Type              Download   Upload \n");

    for (i = 0; i < FILE_ID_MAX; i++)
    {
        const char* type_name = file_type_name(i).c_str();
        if (type_name &&
            (file_stats.files_processed[i][0] || file_stats.files_processed[i][1] ))
        {
            LogMessage("%12s(%3d)          " FMTu64("-10") " " FMTu64("-10") " \n",
                type_name, i,
                file_stats.data_processed[i][0],
                file_stats.data_processed[i][1]);

            processed_data_total[0]+= file_stats.data_processed[i][0];
            processed_data_total[1]+= file_stats.data_processed[i][1];
        }
    }

    LogMessage("            Total          " FMTu64("-10") " " FMTu64("-10") " \n",
        processed_data_total[0], processed_data_total[1]);

    check_total = 0;

    for (i = 0; i < FILE_ID_MAX; i++)
    {
        check_total += file_stats.signatures_processed[i][0];
        check_total += file_stats.signatures_processed[i][1];
    }

    if ( !check_total )
        return;

    LogLabel("file signature stats");

    LogMessage("         Type              Download   Upload \n");

    processed_total[0] = 0;
    processed_total[1] = 0;
    for (i = 0; i < FILE_ID_MAX; i++)
    {
        const char* type_name = file_type_name(i).c_str();
        if (type_name &&
            (file_stats.signatures_processed[i][0] || file_stats.signatures_processed[i][1] ))
        {
            LogMessage("%12s(%3d)          " FMTu64("-10") " " FMTu64("-10") " \n",
                type_name, i,
                file_stats.signatures_processed[i][0], file_stats.signatures_processed[i][1]);
            processed_total[0]+= file_stats.signatures_processed[i][0];
            processed_total[1]+= file_stats.signatures_processed[i][1];
        }
    }
    LogMessage("            Total          " FMTu64("-10") " " FMTu64("-10") " \n",
        processed_total[0], processed_total[1]);

#if 0
    LogLabel("file type verdicts");

    uint64_t verdicts_total = 0;
    for (i = 0; i < FILE_VERDICT_MAX; i++)
    {
        verdicts_total+=file_stats.verdicts_type[i];
        switch (i)
        {
        case FILE_VERDICT_UNKNOWN:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "UNKNOWN",
                file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_LOG:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "LOG",
                file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_STOP:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP",
                file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_BLOCK:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "BLOCK",
                file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_REJECT:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "REJECT",
                file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_PENDING:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "PENDING",
                file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_STOP_CAPTURE:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP CAPTURE",
                file_stats.verdicts_type[i]);
            break;
        default:
            break;
        }
    }
    LogMessage("   %12s:           " FMTu64("-10") " \n", "Total",verdicts_total);

    LogMessage("\nfile signature verdicts:\n");

    verdicts_total = 0;
    for (i = 0; i < FILE_VERDICT_MAX; i++)
    {
        verdicts_total+=file_stats.verdicts_signature[i];
        switch (i)
        {
        case FILE_VERDICT_UNKNOWN:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "UNKNOWN",
                file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_LOG:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "LOG",
                file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_STOP:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP",
                file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_BLOCK:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "BLOCK",
                file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_REJECT:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "REJECT",
                file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_PENDING:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "PENDING",
                file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_STOP_CAPTURE:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP CAPTURE",
                file_stats.verdicts_signature[i]);
            break;
        default:
            break;
        }
    }
    LogMessage("   %12s:           " FMTu64("-10") " \n", "Total",verdicts_total);

    // if (IsAdaptiveConfigured())
    {
        LogMessage("\nfiles processed by protocol IDs:\n");
        for (i = 0; i < MAX_PROTOCOL_ORDINAL; i++)
        {
            if (file_stats.files_by_proto[i])
            {
                LogMessage("   %12d:           " FMTu64("-10") " \n", i,
                    file_stats.files_by_proto[i]);
            }
        }
        LogMessage("\nfile signatures processed by protocol IDs:\n");
        for (i = 0; i < MAX_PROTOCOL_ORDINAL; i++)
        {
            if (file_stats.signatures_by_proto[i])
            {
                LogMessage("   %12d:           " FMTu64(
                        "-10") " \n", i,file_stats.signatures_by_proto[i]);
            }
        }
    }

#endif

    if (file_capture_stats.files_buffered_total || file_capture_stats.file_within_packet)
    {
        LogLabel("file capture stats");
        LogCount("Files buffered", file_capture_stats.files_buffered_total);
        LogCount("Files released", file_capture_stats.files_released_total);
        LogCount("Files freed", file_capture_stats.files_freed_total);
        LogCount("Files captured", file_capture_stats.files_captured_total);
        LogCount("Files within one packet", file_capture_stats.file_within_packet);
        LogCount("Buffers allocated", file_capture_stats.file_buffers_allocated_total);
        LogCount("Buffers freed", file_capture_stats.file_buffers_freed_total);
        LogCount("Buffers released", file_capture_stats.file_buffers_released_total);
        LogCount("Max file buffers used", file_capture_stats.file_buffers_used_max);
        LogCount("Buffers free errors", file_capture_stats.file_buffers_free_errors);
        LogCount("Buffers release errors", file_capture_stats.file_buffers_release_errors);
        LogCount("Total memcap failures", file_capture_stats.file_memcap_failures_total);
        LogCount("Memcap failures at reserve", file_capture_stats.file_memcap_failures_reserve);
        LogCount("Reserve failures", file_capture_stats.file_reserve_failures);
        LogCount("File capture size min", file_capture_stats.file_size_min);
        LogCount("File capture size max", file_capture_stats.file_size_max);
        LogCount("File signature max", file_stats.files_sig_depth);

        FileCapture::print_mem_usage();
    }

    LogLabel("file stats summary");
    LogCount("Files processed",file_stats.files_total);
    LogCount("Files data processed", file_stats.file_data_total);

}

