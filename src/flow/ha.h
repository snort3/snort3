//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
// ha.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef HA_H
#define HA_H

#include <daq_common.h>

#include <cassert>

#include "framework/bits.h"
#include "main/thread.h"

//-------------------------------------------------------------------------

struct HighAvailabilityConfig;

namespace snort
{
class Flow;
struct FlowKey;
struct Packet;
struct ProfileStats;

// The FlowHAHandle is the dynamically allocated index used uniquely identify
//   the client.  Used both in the API and HA messages.
// Handle 0 is defined to be the primary session client.
// NOTE: The type, masks, and count values must be in sync,
typedef uint16_t FlowHAClientHandle;
constexpr FlowHAClientHandle ALL_CLIENTS = 0xffff;

// Each active flow will have an associated FlowHAState instance.
class SO_PUBLIC FlowHAState
{
public:
    static constexpr uint8_t CRITICAL = 0x80;
    static constexpr uint8_t MAJOR = 0x40;

    enum : uint8_t
    {
        NEW = 0x01,
        MODIFIED = 0x02,
        DELETED = 0x04,
        STANDBY = 0x08,
        NEW_SESSION = 0x10,
    };

    FlowHAState();

    void set_pending(FlowHAClientHandle);
    void clear_pending(FlowHAClientHandle);
    bool check_pending(FlowHAClientHandle);
    void set(uint8_t state);
    void add(uint8_t state);
    void clear(uint8_t state);
    bool check_any(uint8_t state);
    static void config_timers(struct timeval, struct timeval);
    bool sync_interval_elapsed();
    void init_next_update();
    void set_next_update();
    void reset();

private:
    static constexpr uint8_t INITIAL_STATE = 0x00;
    static constexpr uint16_t NONE_PENDING = 0x0000;
    static struct timeval min_session_lifetime;
    static struct timeval min_sync_interval;

    struct timeval next_update;
    uint16_t pending = NONE_PENDING;
    uint8_t state = NEW | NEW_SESSION;
};

// Describe the message being produced or consumed.
class HAMessage
{
public:
    HAMessage(uint8_t* buffer, uint32_t buffer_length) :
        buffer(buffer), buffer_length(buffer_length), cursor(buffer) { }

    bool fits(uint32_t size) const { return size <= (buffer_length - (cursor - buffer)); }

    void advance_cursor(uint32_t size)
    {
        assert(fits(size));
        cursor += size;
    }

    void reset_cursor(uint8_t* pos = nullptr)
    {
        if (pos)
        {
            assert(pos >= buffer && pos <= (buffer + buffer_length));
            cursor = pos;
        }
        else
            cursor = buffer;
    }

    uint32_t cursor_position() const { return (uint32_t) (cursor - buffer); }

    uint8_t* buffer;
    const uint32_t buffer_length;
    uint8_t* cursor;
};

// A FlowHAClient subclass for each producer/consumer of flow HA data
class SO_PUBLIC FlowHAClient
{
public:
    virtual ~FlowHAClient() = default;
    virtual bool consume(snort::Flow*&, const snort::FlowKey*, snort::HAMessage&, uint8_t size) = 0;
    virtual bool produce(snort::Flow&, snort::HAMessage&) = 0;
    virtual bool is_update_required(snort::Flow*) { return false; }
    virtual uint8_t get_message_size(Flow&) { return max_length; }

    FlowHAClientHandle handle = 0;  // Actual handle for the instance
    uint8_t index = 0;
    uint8_t max_length;

protected:
    FlowHAClient(uint8_t length, bool session_client);
};

// Top level management of HighAvailability components.
class SO_PUBLIC HighAvailabilityManager
{
public:
    static void configure(HighAvailabilityConfig*);
    static void thread_init();
    static void thread_term_beginning(); // thread is about to be terminated
    static void thread_term();
    static void term();

    // true if we are configured and able to process
    static bool active();

    // Within packet processing, analyze the packet and flow for potential update messages
    static void process_update(snort::Flow*, snort::Packet*);

    // Anytime a flow is deleted, potentially generate a deletion message
    static void process_deletion(snort::Flow&);

    // Look for and dispatch receive messages.
    static void process_receive();
    static void set_modified(snort::Flow*);
    static bool in_standby(snort::Flow*);

    // Attempt to import HA data from the Packet
    static Flow* import(snort::Packet& p, snort::FlowKey& key);

private:
    static void reset_config();

    HighAvailabilityManager() = delete;
    static bool use_daq_channel;
    static PortBitSet* ports;
};
}

#endif

