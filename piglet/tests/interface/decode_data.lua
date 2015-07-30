plugin =
{
    type = "piglet",
    name = "piglet::decode_data",
    test = function()
        -- Put the dofile here so that it doesn't get loaded twice
        dofile(SCRIPT_DIR .. "/common.lua")
        return run_all(tests)
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

tests =
{
    initialize_default = function()
        local dd = DecodeData.new()
        assert(dd)
        assert("default", DEFAULT_VALUES, dd:get())
    end,

    initialize_with_table = function()
        local dd = DecodeData.new(VALUES)
        assert_table_eq("init", VALUES, dd:get())
    end
}
