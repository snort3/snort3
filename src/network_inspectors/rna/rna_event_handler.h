//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "rna_pnd.h"

class RnaAppidEventHandler : public snort::DataHandler
{
public:
    RnaAppidEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaIcmpNewFlowEventHandler : public snort::DataHandler
{
public:
    RnaIcmpNewFlowEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaIcmpBidirectionalEventHandler : public snort::DataHandler
{
public:
    RnaIcmpBidirectionalEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaIpNewFlowEventHandler : public snort::DataHandler
{
public:
    RnaIpNewFlowEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};


class RnaIpBidirectionalEventHandler : public snort::DataHandler
{
public:
    RnaIpBidirectionalEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaTcpSynEventHandler : public snort::DataHandler
{
public:
    RnaTcpSynEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaTcpSynAckEventHandler : public snort::DataHandler
{
public:
    RnaTcpSynAckEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaTcpMidstreamEventHandler : public snort::DataHandler
{
public:
    RnaTcpMidstreamEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaUdpNewFlowEventHandler : public snort::DataHandler
{
public:
    RnaUdpNewFlowEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaUdpBidirectionalEventHandler : public snort::DataHandler
{
public:
    RnaUdpBidirectionalEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaIdleEventHandler : public snort::DataHandler
{
public:
    RnaIdleEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaDHCPInfoEventHandler : public snort::DataHandler
{
public:
    RnaDHCPInfoEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaDHCPDataEventHandler : public snort::DataHandler
{
public:
    RnaDHCPDataEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaFpSMBEventHandler : public snort::DataHandler
{
public:
    RnaFpSMBEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaCPEOSInfoEventHandler : public snort::DataHandler
{
public:
    RnaCPEOSInfoEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

class RnaNetFlowEventHandler : public snort::DataHandler
{
public:
    RnaNetFlowEventHandler(RnaPnd& nd) : DataHandler(RNA_NAME), pnd(nd) { }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    RnaPnd& pnd;
};

#endif
