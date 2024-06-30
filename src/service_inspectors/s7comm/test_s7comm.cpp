#include <iostream>
#include "s7comm.h"
#include "s7comm_decode.h"
#include "protocols/packet.h"

// Example S7comm packet data (Replace this with an actual example)
const uint8_t example_packet[] = {
    0x03, 0x00, 0x00, 0x1F, // TPKT Header
    0x02, 0xF0, 0x80,       // COTP Header
    0x32, 0x01, 0x00, 0x00, // S7comm Header (Protocol ID, Message Type, Reserved)
    0x00, 0x01, 0x00, 0x0A, // PDU Reference, Parameter Length, Data Length
    // Add S7comm data here
};

void run_test()
{
    snort::Packet packet;
    packet.data = const_cast<uint8_t*>(example_packet);
    packet.dsize = sizeof(example_packet);

    // Assuming S7commFlowData and other necessary classes are defined
    S7commFlowData flow_data;
    S7commSessionData session_data;
    flow_data.ssn_data = session_data;

    // Initialize the packet flow data
    packet.flow = new snort::Flow;
    packet.flow->set_flow_data(&flow_data);

    // Call the S7comm decoding function
    if (S7commDecode(&packet, &flow_data))
    {
        std::cout << "S7comm packet decoded successfully." << std::endl;
        // Print decoded fields (for demonstration purposes)
        std::cout << "Protocol ID: " << static_cast<int>(flow_data.ssn_data.s7comm_proto_id) << std::endl;
        std::cout << "Message Type: " << static_cast<int>(flow_data.ssn_data.s7comm_message_type) << std::endl;
        std::cout << "PDU Reference: " << flow_data.ssn_data.s7comm_pdu_reference << std::endl;
        std::cout << "Parameter Length: " << flow_data.ssn_data.s7comm_parameter_length << std::endl;
        std::cout << "Data Length: " << flow_data.ssn_data.s7comm_data_length << std::endl;
    }
    else
    {
        std::cerr << "Failed to decode S7comm packet." << std::endl;
    }

    delete packet.flow; // Clean up
}

int main()
{
    run_test();
    return 0;
}
