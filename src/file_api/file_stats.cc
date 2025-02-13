//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "file_stats.h"

#include "log/log_stats.h"
#include "log/messages.h"
#include "utils/stats.h"
#include "utils/util.h"

#include "file_capture.h"
#include "file_service.h"

using namespace snort;

THREAD_LOCAL FileCounts file_counts;
THREAD_LOCAL FileStats* file_stats = nullptr;

static FileStats file_totals;

void file_stats_init()
{
    file_stats = (FileStats*)snort_calloc(sizeof(*file_stats));
}

void file_stats_term()
{
    snort_free(file_stats);
}

void file_stats_sum()
{
    if (!file_stats)
        return;

    unsigned num = sizeof(file_totals) / sizeof(PegCount);

    PegCount* t = (PegCount*)&file_totals;
    PegCount* s = (PegCount*)file_stats;

    for (unsigned i = 0; i < num; ++i)
        t[i] += s[i];

    memset(file_stats, 0, sizeof(*file_stats));
}

void file_stats_clear()
{
    memset(&file_counts, 0, sizeof(file_counts));
    memset(&file_totals, 0, sizeof(file_totals));
    if (file_stats)
        memset(file_stats, 0, sizeof(*file_stats));
}

void file_stats_print()
{
    uint64_t processed_total[2];
    uint64_t processed_data_total[2];
    uint64_t processed_sig_total[2]{ 0, 0 };
    uint64_t check_total = 0;
    uint64_t check_sig_total{ 0 };

    for (unsigned i = 0; i < FILE_ID_MAX; i++)
    {
        check_total += file_totals.files_processed[i][0];
        check_total += file_totals.files_processed[i][1];
    }

    if ( !check_total )
        return;

    for (unsigned i = 0; i < FILE_ID_MAX; i++)
    {
        check_sig_total += file_totals.signatures_processed[i][0];
        check_sig_total += file_totals.signatures_processed[i][1];
    }

    LogLabel("File Statistics");
    LogLabel("file stats");

    char buff[128];
    if (FileService::is_file_signature_enabled() && check_sig_total)
        snprintf(buff, sizeof(buff), "%25.25s %-10s %-10s %-10s %-10s %-10s %-10s", "Type",
            "TypeDn", "TypeUp", "SigDn", "SigUp", "BytesDn", "BytesUp");
    else
        snprintf(buff, sizeof(buff), "%25.25s %-10s %-10s %-10s %-10s", "Type", "TypeDn", "TypeUp",
            "BytesDn", "BytesUp");
    LogText(buff);

    processed_total[0] = 0;
    processed_total[1] = 0;
    processed_data_total[0] = 0;
    processed_data_total[1] = 0;
    processed_sig_total[0]  = 0;
    processed_sig_total[1]  = 0;

    for (unsigned i = 0; i < FILE_ID_MAX; i++)
    {
        std::string type_name  = file_type_name(i);
        bool status = false;

        if (FileService::is_file_signature_enabled() && check_sig_total)
            status = ( file_totals.files_processed[i][0] ||
                file_totals.files_processed[i][1] ||
                file_totals.signatures_processed[i][0] ||
                file_totals.signatures_processed[i][1] );
        else
            status = ( file_totals.files_processed[i][0] ||
                file_totals.files_processed[i][1] );

        if (type_name.length() && status)
        {
            type_name.append("(");
            type_name.append(std::to_string(i));
            type_name.append(")");
            if (FileService::is_file_signature_enabled() && check_sig_total)
            {
                snprintf(buff, sizeof(buff), "%25.25s " FMTu64("-10") " " FMTu64("-10") " "
                    FMTu64("-10") " " FMTu64("-10") " " FMTu64("-10") " " FMTu64("-10"),
                    type_name.c_str(), file_totals.files_processed[i][0],
                    file_totals.files_processed[i][1],
                    file_totals.signatures_processed[i][0],
                    file_totals.signatures_processed[i][1],
                    file_totals.data_processed[i][0],
                    file_totals.data_processed[i][1]);
            }
            else
            {
                snprintf(buff, sizeof(buff), "%25.25s " FMTu64("-10") " " FMTu64("-10") " "
                    FMTu64("-10") " " FMTu64("-10"),
                    type_name.c_str(),
                    file_totals.files_processed[i][0],
                    file_totals.files_processed[i][1],
                    file_totals.data_processed[i][0],
                    file_totals.data_processed[i][1]);
            }
            LogText(buff);
            processed_total[0]      += file_totals.files_processed[i][0];
            processed_total[1]      += file_totals.files_processed[i][1];
            processed_data_total[0] += file_totals.data_processed[i][0];
            processed_data_total[1] += file_totals.data_processed[i][1];
            if (FileService::is_file_signature_enabled() && check_sig_total)
            {
                processed_sig_total[0]  += file_totals.signatures_processed[i][0];
                processed_sig_total[1]  += file_totals.signatures_processed[i][1];
            }
        }
    }

    if (FileService::is_file_signature_enabled() && check_sig_total)
    {
        snprintf(buff, sizeof(buff), "%25.25s " FMTu64("-10") " " FMTu64("-10") " "
            FMTu64("-10") " " FMTu64("-10") " " FMTu64("-10") " " FMTu64("-10"),
            "Total", processed_total[0], processed_total[1], processed_sig_total[0],
            processed_sig_total[1], processed_data_total[0], processed_data_total[1]);
    }
    else
    {
        snprintf(buff, sizeof(buff), "%25.25s " FMTu64("-10") " " FMTu64("-10") " "
            FMTu64("-10") " " FMTu64("-10"),"Total", processed_total[0],
            processed_total[1], processed_data_total[0], processed_data_total[1]);
    }
    LogText(buff);

#if 0
    LogLabel("file type verdicts");  // FIXIT-RC should be fixed

    uint64_t verdicts_total = 0;#include "file_capture.h"
    for (unsigned i = 0; i < FILE_VERDICT_MAX; i++)
    {
        verdicts_total+=file_totals.verdicts_type[i];
        switch (i)
        {
        case FILE_VERDICT_UNKNOWN:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "UNKNOWN",
                file_totals.verdicts_type[i]);
            break;
        case FILE_VERDICT_LOG:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "LOG",
                file_totals.verdicts_type[i]);
            break;
        case FILE_VERDICT_STOP:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP",
                file_totals.verdicts_type[i]);
            break;
        case FILE_VERDICT_BLOCK:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "BLOCK",
                file_totals.verdicts_type[i]);
            break;
        case FILE_VERDICT_REJECT:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "REJECT",
                file_totals.verdicts_type[i]);
            break;
        case FILE_VERDICT_PENDING:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "PENDING",
                file_totals.verdicts_type[i]);
            break;
        case FILE_VERDICT_STOP_CAPTURE:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP CAPTURE",
                file_totals.verdicts_type[i]);
            break;
        default:
            break;
        }
    }
    LogMessage("   %12s:           " FMTu64("-10") " \n", "Total",verdicts_total);

    LogMessage("\nfile signature verdicts:\n");

    verdicts_total = 0;
    for (unsigned i = 0; i < FILE_VERDICT_MAX; i++)
    {
        verdicts_total+=file_totals.verdicts_signature[i];
        switch (i)
        {
        case FILE_VERDICT_UNKNOWN:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "UNKNOWN",
                file_totals.verdicts_signature[i]);
            break;
        case FILE_VERDICT_LOG:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "LOG",
                file_totals.verdicts_signature[i]);
            break;
        case FILE_VERDICT_STOP:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP",
                file_totals.verdicts_signature[i]);
            break;
        case FILE_VERDICT_BLOCK:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "BLOCK",
                file_totals.verdicts_signature[i]);
            break;
        case FILE_VERDICT_REJECT:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "REJECT",
                file_totals.verdicts_signature[i]);
            break;
        case FILE_VERDICT_PENDING:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "PENDING",
                file_totals.verdicts_signature[i]);
            break;
        case FILE_VERDICT_STOP_CAPTURE:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP CAPTURE",
                file_totals.verdicts_signature[i]);
            break;
        default:
            break;
        }
    }
    LogMessage("   %12s:           " FMTu64("-10") " \n", "Total",verdicts_total);

    // if (IsAdaptiveConfigured())
    {
        LogMessage("\nfiles processed by protocol IDs:\n");
        for (unsigned i = 0; i < MAX_PROTOCOL_ORDINAL; i++)
        {
            if (file_totals.files_by_proto[i])
            {
                LogMessage("   %12d:           " FMTu64("-10") " \n", i,
                    file_totals.files_by_proto[i]);
            }
        }
        LogMessage("\nfile signatures processed by protocol IDs:\n");
        for (unsigned i = 0; i < MAX_PROTOCOL_ORDINAL; i++)
        {
            if (file_totals.signatures_by_proto[i])
            {
                LogMessage("   %12d:           " FMTu64(
                        "-10") " \n", i,file_totals.signatures_by_proto[i]);
            }
        }
    }

#endif
    // these are global / shared by all threads
    FileCapture::print_mem_usage();
}

