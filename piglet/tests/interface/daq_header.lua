plugin =
{
    type = "piglet",
    name = "piglet::daq_header",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

DEFAULT_VALUES =
{
    caplen = 0,
    pktlen = 0,
    ingress_index = 0,
    egress_index = 0,
    ingress_group = 0,
    egress_group = 0,
    flags = 0,
    opaque = 0,
    flow_id = 0,
    address_space_id = 0
}

VALUES =
{
    caplen = 1,
    pktlen = 2,
    ingress_index = 3,
    egress_index = 4,
    ingress_group = 5,
    egress_group = 6,
    flags = 7,
    opaque = 8,
    flow_id = 9,
    address_space_id = 10
}

tests =
{
    initialize_default = function()
        local daq = DAQHeader.new()
        assert(daq)
        check.tables_equal(DEFAULT_VALUES, daq:get())
    end,

    initialize_with_table = function()
        local daq = DAQHeader.new(VALUES)
        check.tables_equal(VALUES, daq:get())
    end
}
