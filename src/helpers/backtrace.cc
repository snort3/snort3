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
// backtrace.cc author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "backtrace.h"

void print_backtrace([[maybe_unused]] SigSafePrinter& ssp)
{
#ifdef HAVE_LIBUNWIND
    int ret;

    // grab the machine context and initialize the cursor
    unw_context_t context;
    if ((ret = unw_getcontext(&context)) < 0)
    {
        ssp.printf("unw_getcontext failed: %s (%d)\n", unw_strerror(ret), ret);
        return;
    }

    unw_cursor_t cursor;
    if ((ret = unw_init_local(&cursor, &context)) < 0)
    {
        ssp.printf("unw_init_local failed: %s (%d)\n", unw_strerror(ret), ret);
        return;
    }

    ssp.printf("Backtrace:\n");

    // walk the stack frames
    unsigned frame_num = 0;
#ifndef __APPLE__
    // Apple's libunwind doesn't support unw_is_signal_frame, so print all frames there
    bool signal_frame_found = false;
#endif

    while ((ret = unw_step(&cursor)) > 0)
    {
#ifndef __APPLE__
        if (!signal_frame_found)
        {
            if (unw_is_signal_frame(&cursor))
            {
                signal_frame_found = true;
#ifdef __aarch64__
                // skip __kernel_rt_sigreturn in vDSO for arm
                continue;
#endif
            }
            else
                continue;
        }
#endif

        unw_word_t pc;
        if ((ret = unw_get_reg(&cursor, UNW_REG_IP, &pc)) < 0)
        {
            ssp.printf("unw_get_reg failed for instruction pointer: %s (%d)\n",
                    unw_strerror(ret), ret);
            return;
        }


        ssp.printf("  #%u 0x%x", static_cast<uint64_t>(frame_num), static_cast<uint64_t>(pc));

        char sym[1024];
        unw_word_t offset;
        ret = unw_get_proc_name(&cursor, sym, sizeof(sym), &offset);
        switch (-ret)
        {
            case 0:
                // fallthrough
            case UNW_ENOMEM:
                ssp.printf(" in %s+0x%x", sym, static_cast<uint64_t>(offset));
                break;
            case UNW_ENOINFO:
                // fallthrough
            case UNW_EUNSPEC:
                // fallthrough
            default:
                ssp.printf(" unw_get_proc_name failed: %s (%d)", unw_strerror(ret), ret);
                break;
        }

        unw_proc_info_t pip;
        if ((ret = unw_get_proc_info(&cursor, &pip)) < 0)
        {
            ssp.printf(" unw_get_proc_info failed: %s (%d)", unw_strerror(ret), ret);
        }
        else
        {
            Dl_info dlinfo;
            if (dladdr((void*) (uintptr_t) (pip.start_ip + offset), &dlinfo)
                && dlinfo.dli_fname && *dlinfo.dli_fname)
            {
                ssp.printf(" (%s @0x%x)", dlinfo.dli_fname, static_cast<uint64_t>((uintptr_t)dlinfo.dli_fbase));
            }
        }

        ssp.printf("\n");

        frame_num++;
    }
    if (ret < 0)
        ssp.printf("unw_step failed: %s (%d)\n", unw_strerror(ret), ret);

    ssp.printf("\n");
#else
    return;
#endif
}

