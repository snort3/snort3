plugin =
{
    type = "piglet",
    name = "piglet::decode_data",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

DEFAULT_VALUES =
{
    sp = 0,
    dp = 0,
    decode_flags = 0,
    type = 0
}

VALUES =
{
    sp = 1,
    dp = 2,
    decode_flags = 3,
    type = 4
}

IP4 = [[
45  | 00  | 00  46 | 00 00 | 00 00 | 01 | 06
00 00 | 00 00 00 01 | 00 00 00 02

00 00 | 00 00 | 00 00 00 00 | 00 00 00 00 | 06 02
00 00 ff ff | 00 00 | 00 00 | 00 00
]]

tests =
{
    initialize_default = function()
        local dd = DecodeData.new()
        assert(dd)
        check.tables_equal(DEFAULT_VALUES, dd:get())
    end,

    initialize_with_table = function()
        local dd = DecodeData.new(VALUES)
        check.tables_equal(VALUES, dd:get())
    end,

    ip_api = function()
        local dd = DecodeData.new(VALUES)
        local ip = dd:get_ip_api()
        local raw = IP4:encode_hex()
        ip:set_ip4(raw)
    end
}
