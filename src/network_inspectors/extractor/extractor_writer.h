//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// extractor_writer.h author Anna Norokh <anorokh@cisco.com>

#ifndef EXTRACTOR_WRITER_H
#define EXTRACTOR_WRITER_H

#include <mutex>
#include <string>

class OutputType
{
public:
    enum Value : uint8_t
    {
        STD,
        MAX
    };

    OutputType() = default;
    constexpr OutputType(Value a) : v(a) {}
    template<typename T> constexpr OutputType(T a) : v((Value)a) {}

    constexpr operator Value() const { return v; }
    explicit operator bool() const = delete;

    const char* c_str() const
    {
        switch (v)
        {
        case STD:
            return "stdout";
        case MAX: // fallthrough
        default:
            return "(not set)";
        }
    }

private:
    Value v = STD;
};

class ExtractorWriter
{
public:
    static ExtractorWriter* make_writer(OutputType);

    ExtractorWriter(const ExtractorWriter&) = delete;
    ExtractorWriter& operator=(const ExtractorWriter&) = delete;
    ExtractorWriter(ExtractorWriter&&) = delete;

    virtual ~ExtractorWriter() = default;

    virtual void write(const char*) = 0;
    virtual void lock() { }
    virtual void unlock() { }

protected:
    ExtractorWriter() = default;
};

class StdExtractorWriter : public ExtractorWriter
{
public:
    StdExtractorWriter() = default;

    void write(const char* ss) override
    { fprintf(stdout, "%s", ss); }

    void lock() override
    { write_mutex.lock(); }

    void unlock() override
    { write_mutex.unlock(); }

private:
    std::mutex write_mutex;
};

#endif
