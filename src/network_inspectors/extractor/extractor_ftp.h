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
// extractor_ftp.h author Anna Norokh <anorokh@cisco.com>

#ifndef EXTRACTOR_FTP_H
#define EXTRACTOR_FTP_H

#include <cassert>

#include "extractors.h"

class FtpExtractorFlowData;

class FtpRequestExtractor : public ExtractorEvent
{
public:
    FtpRequestExtractor(Extractor&, ExtractorLogger&, uint32_t tenant, const std::vector<std::string>& fields);

    void handle(DataEvent&, Flow*);

private:
    using Req = Handler<FtpRequestExtractor>;
};

class FtpResponseExtractor : public ExtractorEvent
{
public:
    using SubGetFn = int8_t (*) (const DataEvent*, const Packet*, const Flow*);
    using SubField = DataField<int8_t, const DataEvent*, const Packet*, const Flow*>;

    FtpResponseExtractor(Extractor&, ExtractorLogger&, uint32_t tenant, const std::vector<std::string>& fields);

    std::vector<const char*> get_field_names() const override;
    void handle(DataEvent&, Flow*);

private:
    using Resp = Handler<FtpResponseExtractor>;

    std::vector<SubField> sub_fields;
};

class FtpExtractor : public ExtractorEvent
{
public:
    using FdBufGetFn = const char* (*) (const FtpExtractorFlowData&);
    using FdBufField = DataField<const char*, const FtpExtractorFlowData&>;
    using FdSipGetFn = const SfIp& (*) (const FtpExtractorFlowData&);
    using FdSipField = DataField<const SfIp&, const FtpExtractorFlowData&>;
    using FdNumGetFn = uint64_t (*) (const FtpExtractorFlowData&);
    using FdNumField = DataField<uint64_t, const FtpExtractorFlowData&>;
    using FdSubGetFn = int8_t (*) (const FtpExtractorFlowData&);
    using FdSubField = DataField<int8_t, const FtpExtractorFlowData&>;

    FtpExtractor(Extractor&, ExtractorLogger&, uint32_t tenant, const std::vector<std::string>& fields);

    std::vector<const char*> get_field_names() const override;
    void dump(const FtpExtractorFlowData&);

private:
    struct Req : public DataHandler
    {
        Req(FtpExtractor& owner, const char* name) : DataHandler(name), owner(owner) {}
        void handle(DataEvent&, Flow*) override;
        FtpExtractor& owner;
    };

    struct Resp : public DataHandler
    {
        Resp(FtpExtractor& owner, const char* name) : DataHandler(name), owner(owner) {}
        void handle(DataEvent&, Flow*) override;
        FtpExtractor& owner;
    };

    std::vector<FdBufField> fd_buf_fields;
    std::vector<FdSipField> fd_sip_fields;
    std::vector<FdNumField> fd_num_fields;
    std::vector<FdSubField> fd_sub_fields;
};

#endif
