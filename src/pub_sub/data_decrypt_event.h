//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
//--------------------------------------------------------------------------

#ifndef DATA_DECRYPT_EVENT_H
#define DATA_DECRYPT_EVENT_H

#define DATA_DECRYPT_EVENT "Data Decrypt event"

class DataDecryptEvent : public snort::DataEvent
{
public:

    enum StateEventType : uint16_t
    {
        DATA_DECRYPT_MONITOR_EVENT,
        DATA_DECRYPT_DO_NOT_DECRYPT_EVENT,
        DATA_DECRYPT_START_EVENT
    };

    DataDecryptEvent(const StateEventType& type)  : m_type(type)  { }
    StateEventType get_type() const { return m_type; }

private:
    StateEventType m_type;
};


#endif //DATA_DECRYPT_EVENT_H

