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
// alt_signal_stack.h author Cisco

#ifndef ALT_SIGNAL_STACK_H
#define ALT_SIGNAL_STACK_H

#include <csignal>
#include <cstdint>

#include "log/messages.h"

// 8192 -> 8Kb hardcoded size if SIGSTKSZ is not available (or not defined)
static __attribute__((constructor)) size_t get_stack_size()
{
    static const size_t size = [] {
        const int sigstk = SIGSTKSZ;
        return (sigstk > 0) ? static_cast<size_t>(sigstk) : 8192;
    }();
    return size;
}

// Each thread requires its own alternate signal stack
// To avoid rewriting the stack with other threads' data, the alt stack pointer buffer should be THREAD_LOCAL
static uint8_t* create_alt_signal_stack()
{
#ifndef HAVE_SIGACTION
    return nullptr;
#else
    const size_t stack_size = get_stack_size();
    uint8_t* alt_signal_stack = new uint8_t[stack_size];

    stack_t ss { };
    ss.ss_sp = alt_signal_stack;
    ss.ss_size = stack_size;
    ss.ss_flags = 0;

    if (sigaltstack(&ss, NULL) != 0)
    {
        snort::ErrorMessage("Failed to initialize alternate signal stack: %s (%d)\n", strerror(errno), errno);
        delete[] alt_signal_stack;
        alt_signal_stack = nullptr;
    }

    return alt_signal_stack;
#endif
}

static void term_alt_signal_stack(uint8_t*& alt_signal_stack)
{
#ifndef HAVE_SIGACTION
    (void)alt_signal_stack;
#else
    if (!alt_signal_stack)
        return;

    stack_t ss { };
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, nullptr);

    delete[] alt_signal_stack;
    alt_signal_stack = nullptr;
#endif
}

#endif
