plugin =
{
    type = "piglet",
    name = "piglet::packet",
    test = function()
        -- Put the dofile here so that it doesn't get loaded twice
        dofile(SCRIPT_DIR .. "/common.lua")
        return run_all(tests)
    end
}

DEFAULT_VALUES =
{
    packet_flags = 0,
    xtradata_mask = 0,
    proto_bits = 0,
    application_protocol_ordinal = 0,
    alt_dsize = 0,
    num_layers = 0,
    iplist_id = 0,
    user_policy_id = 0,
    ps_proto = 0
}

VALUES =
{
    packet_flags = 1,
    xtradata_mask = 2,
    proto_bits = 3,
    application_protocol_ordinal = 4,
    alt_dsize = 5,
    num_layers = 6,
    iplist_id = 7,
    user_policy_id = 8,
    ps_proto = 9
}

tests =
{
    initialize_default = function()
        local p = Packet.new()
        assert(p)
    end,

    initialize_with_data = function()
        local rb = RawBuffer.new()
        local p = Packet.new(rb)
        assert(p)
    end,

    initialize_with_daq = function()
        local rb = RawBuffer.new()
        local daq = DAQHeader.new()
        local p = Packet.new(rb, daq)
        assert(p)
    end,

    set_decode_data = function()
        local p = Packet.new()
        local dd = DecodeData.new()
        p:set_decode_data(dd)
    end,

    set_data = function()
        local rb = RawBuffer.new()
        local p = Packet.new(rb)
        p:set_data(1, 2)
    end,

    set_flow = function()
        local flow = Flow.new()
        local p = Packet.new()
        p:set_flow(flow)
    end,

    get_and_set = function()
        local p = Packet.new()
        assert_table_eq("get()", DEFAULT_VALUES, p:get())
        p:set(VALUES)
        assert_table_eq("set()", VALUES, p:get())
    end,

    set_pkt = function()
        local rb = RawBuffer.new()
        local p = Packet.new()
        p:set_pkt(rb)
    end,

    set_daq = function()
        local daq = DAQHeader.new()
        local p = Packet.new()
        p:set_daq(daq)
    end
}
