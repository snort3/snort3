//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// mitigator_exception.cc author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mitigator_exception.h"

#include <csignal>

#include "helpers/backtrace.h"
#include "helpers/sigsafe.h"
#include "main/oops_handler.h"
#include "utils/cpp_macros.h"
#include "utils/util.h"

namespace snort
{

void MitigationException::print_mitigation_info(int32_t signal, bool accepted)
{
    const char* sigstr = "???\n";
    switch (signal)
    {
    case SIGILL:
        sigstr = STRINGIFY(SIGILL) " (" STRINGIFY_MX(SIGILL) ")";
        break;
    case SIGABRT:
        sigstr = STRINGIFY(SIGABRT) " (" STRINGIFY_MX(SIGABRT) ")";
        break;
    case SIGBUS:
        sigstr = STRINGIFY(SIGBUS) " (" STRINGIFY_MX(SIGBUS) ")";
        break;
    case SIGFPE:
        sigstr = STRINGIFY(SIGFPE) " (" STRINGIFY_MX(SIGFPE) ")";
        break;
    case SIGSEGV:
        sigstr = STRINGIFY(SIGSEGV) " (" STRINGIFY_MX(SIGSEGV) ")";
        break;
    }

    SigSafePrinter ssp(STDERR_FILENO);

    if (accepted)
        ssp.printf("\nSnort (PID %u) mitigated signal: %s\n", getpid(), sigstr);
    else
        ssp.printf("\nSnort (PID %u) choked with signal: %s\n", getpid(), sigstr);

#ifdef BUILD
    ssp.printf("Version: %s Build %s\n\n", VERSION, BUILD);
#else
    ssp.printf("Version: %s\n\n", VERSION);
#endif

    // Try to pretty-print a stack trace using libunwind to traverse the stack.
    print_backtrace(ssp);

    OopsHandler::handle_crash(STDERR_FILENO);
}

} // namespace snort
