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
// js_pdf_norm_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "catch/catch.hpp"

#include "js_norm/js_pdf_norm.h"

using namespace snort;

// cppcheck-suppress-begin comparisonOfFuncReturningBoolError ; Catch2 false positive
TEST_CASE("PDF file detection", "[PDFJSNorm]")
{
    SECTION("valid headers")
    {
        CHECK(PDFJSNorm::is_pdf("%PDF-1.0\n", 9));
        CHECK(PDFJSNorm::is_pdf("%PDF-1.7\r", 9));
        CHECK(PDFJSNorm::is_pdf("%PDF-2.0\r\n", 10));
        CHECK(PDFJSNorm::is_pdf("%PDF-2.9\n", 9));
    }

    SECTION("arbitrary binary prefix")
    {
        std::string pdf("prefix");
        pdf.push_back('\0');
        pdf += "%PDF-2.0\n";

        CHECK(PDFJSNorm::is_pdf(pdf.data(), pdf.size()));
    }

    SECTION("1024 byte scan limit")
    {
        std::string within_limit(1015, 'x');
        within_limit += "%PDF-1.7\n";
        CHECK(PDFJSNorm::is_pdf(within_limit.data(), within_limit.size()));

        std::string beyond_limit(1016, 'x');
        beyond_limit += "%PDF-1.7\n";
        CHECK_FALSE(PDFJSNorm::is_pdf(beyond_limit.data(), beyond_limit.size()));
    }

    SECTION("invalid headers")
    {
        CHECK_FALSE(PDFJSNorm::is_pdf(nullptr, 9));
        CHECK_FALSE(PDFJSNorm::is_pdf("%PDF-1.7", 8));
        CHECK_FALSE(PDFJSNorm::is_pdf("%PDF-1.x\n", 9));
        CHECK_FALSE(PDFJSNorm::is_pdf("%PDF-1.70\n", 10));
        CHECK_FALSE(PDFJSNorm::is_pdf("%PDF-3.0\n", 9));
    }
}
// cppcheck-suppress-end comparisonOfFuncReturningBoolError
