plugin =
{
    type = "piglet",
    name = "piglet::packet",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
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

    init_with_string = function()
        local p = Packet.new("foobar")
        assert(p)
    end,

    init_with_size = function()
        local p = Packet.new(128)
        assert(p)
    end,

    init_with_raw_buffer = function()
        local rb = RawBuffer.new()
        local p = Packet.new(rb)
        assert(p)
    end,

    init_with_daq = function()
        local daq = DAQHeader.new()
        local p = Packet.new(daq)
        assert(p)
    end,

    init_with_table = function()
        local p = Packet.new(VALUES)
        check.tables_equal(VALUES, p:get())
    end,

    init_with_everything = function()
        local p = Packet.new("foobar", DAQHeader.new(), { packet_flags = 4 })
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
        check.tables_equal(DEFAULT_VALUES, p:get())
        p:set(VALUES)
        check.tables_equal(VALUES, p:get())
    end
}
