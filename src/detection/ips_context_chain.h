//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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

// ips_context_chain.h author Carter Waxman <cwaxman@cisco.com>

#ifndef IPS_CONTEXT_CHAIN_H
#define IPS_CONTEXT_CHAIN_H

// IpsContextChain provides an interface for maintaining dependencies between
// IpsContexts. This class is provided to handle all linking and ensure only
// the tips of dependency chains are able to be processed, enforcing strict
// processing order.

namespace snort
{
class IpsContext;
class IpsContextChain
{
public:
    void abort()
    { _front = _back = nullptr; }

    IpsContext* front() const
    { return _front; }

    IpsContext* back() const
    { return _back; }

    void pop();
    void push_back(IpsContext*);

private:
    IpsContext* _front = nullptr;
    IpsContext* _back = nullptr;
};
}

#endif

