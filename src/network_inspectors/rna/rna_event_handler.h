//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// rna_event_handler.h author Masud Hasan <mashasan@cisco.com>

#ifndef RNA_EVENT_HANDLER_H
#define RNA_EVENT_HANDLER_H

#include "framework/data_bus.h"

#include "rna_module.h"

class RnaIcmpEventHandler : public snort::DataHandler
{
public:
    RnaIcmpEventHandler() : DataHandler(RNA_NAME) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
};

class RnaIpEventHandler : public snort::DataHandler
{
public:
    RnaIpEventHandler() : DataHandler(RNA_NAME) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
};

class RnaUdpEventHandler : public snort::DataHandler
{
public:
    RnaUdpEventHandler() : DataHandler(RNA_NAME) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
};

class RnaTcpSynEventHandler : public snort::DataHandler
{
public:
    RnaTcpSynEventHandler() : DataHandler(RNA_NAME) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
};

class RnaTcpSynAckEventHandler : public snort::DataHandler
{
public:
    RnaTcpSynAckEventHandler() : DataHandler(RNA_NAME) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
};

class RnaTcpMidstreamEventHandler : public snort::DataHandler
{
public:
    RnaTcpMidstreamEventHandler() : DataHandler(RNA_NAME) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
};

#endif
