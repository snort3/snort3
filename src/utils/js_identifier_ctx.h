//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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
// js_identifier_ctx.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef JS_IDENTIFIER_CTX
#define JS_IDENTIFIER_CTX

#include <string>
#include <unordered_map>

class JSIdentifierCtxBase
{
public:
    virtual ~JSIdentifierCtxBase() = default;

    virtual const char* substitute(const char* identifier) = 0;
    virtual void reset() = 0;
    virtual size_t size() const = 0;
};

class JSIdentifierCtx : public JSIdentifierCtxBase
{
public:
    JSIdentifierCtx(int32_t depth) : depth(depth) {}

    const char* substitute(const char* identifier) override;
    void reset() override;

    // approximated to 500 unique mappings insertions
    size_t size() const override
    { return (sizeof(JSIdentifierCtx) + (sizeof(std::string) * 2 * 500)); }

private:
    int32_t ident_last_name = 0;
    int32_t depth;

    std::unordered_map<std::string, std::string> ident_names;
};

#endif // JS_IDENTIFIER_CTX

