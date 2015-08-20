plugin =
{
    type = "piglet",
    name = "piglet::codec_data",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

INIT_PROTO = 1

DEFAULT_VALUES =
{
    next_prot_id = 0,
    lyr_len = 0,
    invalid_bytes = 0,
    proto_bits = 0,
    codec_flags = 0,
    ip_layer_cnt = 0,
    ip6_extension_count = 0,
    curr_ip6_extension = 0,
    ip6_csum_proto = 0
}

VALUES =
{
    next_prot_id = 1,
    lyr_len = 2,
    invalid_bytes = 3,
    proto_bits = 4,
    codec_flags = 5,
    ip_layer_cnt = 6,
    ip6_extension_count = 7,
    curr_ip6_extension = 8,
    ip6_csum_proto = 9
}

tests =
{
    initialize_default = function()
        local cd = CodecData.new()
        assert(cd)
        assert(cd:get().next_prot_id == 0)
    end,

    initialize_with_number = function()
        local cd = CodecData.new(INIT_PROTO)
        assert(cd:get().next_prot_id == INIT_PROTO)
    end,

    initialize_with_table = function()
        local cd = CodecData.new()
        check.tables_equal(DEFAULT_VALUES, cd:get())
        cd:set(VALUES)
        check.tables_equal(VALUES, cd:get())
    end
}
